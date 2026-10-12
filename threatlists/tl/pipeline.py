"""Pipeline: fontes + inbox → listas. Determinístico, sem estado fora do repositório. Só stdlib (Python ≥ 3.11)."""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import ioc as I
from .allow import Allowlist
from .sources import Result, Source, load

# nome do ficheiro → (tipo, nível). Os hashes não têm nível: uma só lista por algoritmo.
FEEDS: Dict[str, Tuple[str, Optional[str]]] = {
    "ip-block.txt": ("ip", "block"),
    "ip-monitor.txt": ("ip", "monitor"),
    "domain-block.txt": ("domain", "block"),
    "domain-monitor.txt": ("domain", "monitor"),
    "hash-md5.txt": ("md5", None),
    "hash-sha1.txt": ("sha1", None),
    "hash-sha256.txt": ("sha256", None),
}

DEFAULTS: Dict[str, Any] = {
    "policy": {"min_prefix_v4": 16, "inbox_default_ttl_days": 30, "inbox_default_class": "block"},
    "breaker": {"min_previous": 50, "max_change_pct": 50},
    "limits": {"ip-block.txt": 30000, "ip-monitor.txt": 60000, "domain-block.txt": 50000, "domain-monitor.txt": 100000,
               "hash-md5.txt": 100000, "hash-sha1.txt": 100000, "hash-sha256.txt": 100000},
    "allowlist": {"files": ["threatlists/allowlist.txt"], "external": []},
}


def load_config(path: Path) -> Dict[str, Any]:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    cfg: Dict[str, Any] = {k: dict(v) if isinstance(v, dict) else v for k, v in DEFAULTS.items()}
    for section in ("policy", "breaker", "limits", "allowlist"):
        cfg[section] = {**DEFAULTS[section], **raw.get(section, {})}
    cfg["sources"] = [Source.from_dict(d) for d in raw.get("source", [])]
    ids = [s.id for s in cfg["sources"]]
    if len(ids) != len(set(ids)):
        raise ValueError("ids de fontes repetidos em config.toml")
    return cfg


# ── Allowlist ────────────────────────────────────────────────────────────────────

def load_allowlist(root: Path, cfg: Dict[str, Any]) -> Allowlist:
    al = Allowlist()
    for rel in cfg["allowlist"]["files"] + cfg["allowlist"]["external"]:   # 'external' = listas do repositório, só lidas
        p = root / rel
        if p.is_file():
            al.add_text(p.read_text(encoding="utf-8", errors="replace"))
    return al


# ── Inbox (entradas injetadas: CNCS, manuais) ─────────────────────────────────────

_HDR = re.compile(r"^#\s*([A-Za-z_]+)\s*:\s*(.*?)\s*$")


@dataclass
class InboxEntry:
    path: Path
    origin: str
    ref: str
    cls: str
    added: date
    expires: date
    iocs: List[I.IOC] = field(default_factory=list)


def _d(s: str) -> date:
    return datetime.strptime(s.strip(), "%Y-%m-%d").date()


def read_inbox(root: Path, cfg: Dict[str, Any], today: date, prune: bool = False) -> Tuple[List[InboxEntry], List[str]]:
    """Lê threatlists/inbox/**/*.txt. Cabeçalho '# chave: valor'; o resto são IOCs (aceita ofuscação). Devolve (válidas, avisos)."""
    notes: List[str] = []
    out: List[InboxEntry] = []
    base = root / "threatlists" / "inbox"
    if not base.is_dir():
        return out, notes
    for p in sorted(base.rglob("*.txt")):
        rel = p.relative_to(root).as_posix()
        text = p.read_text(encoding="utf-8", errors="replace")
        hdr: Dict[str, str] = {}
        body: List[str] = []
        for line in text.splitlines():
            m = _HDR.match(line)
            if m:
                hdr[m.group(1).lower()] = m.group(2)
            elif not line.lstrip().startswith("#"):
                body.append(line)
        try:
            added = _d(hdr["added"])
            expires = _d(hdr["expires"]) if hdr.get("expires") else added + timedelta(days=int(cfg["policy"]["inbox_default_ttl_days"]))
        except (KeyError, ValueError):
            notes.append(f"inbox: {rel} ignorado (falta '# added: AAAA-MM-DD' ou a data é inválida)")
            continue
        cls = (hdr.get("class") or cfg["policy"]["inbox_default_class"]).lower()
        if cls not in ("block", "monitor"):
            notes.append(f"inbox: {rel} ignorado (class '{cls}' inválida: block ou monitor)")
            continue
        if expires < today:
            if prune:
                p.unlink()
                notes.append(f"inbox: {rel} expirou em {expires} e foi apagado")
            else:
                notes.append(f"inbox: {rel} expirado em {expires} (ignorado)")
            continue
        ex = I.extract("\n".join(body), cfg["policy"]["min_prefix_v4"])
        out.append(InboxEntry(p, hdr.get("origin") or p.parent.name, hdr.get("ref", ""), cls, added, expires, ex["iocs"]))   # type: ignore[arg-type]
        for val, why in ex["rejected"]:                                                                                     # type: ignore[union-attr]
            notes.append(f"inbox: {rel}: '{val}' recusado ({why})")
    return out, notes


# ── Classificação ────────────────────────────────────────────────────────────────

def classify(results: List[Result], inbox: List[InboxEntry], allow: Allowlist) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
    """block = fonte de confiança 'high', OU 2+ fontes independentes, OU injetado como block; senão monitor."""
    votes: Dict[I.IOC, Set[str]] = {}
    forced: Set[I.IOC] = set()
    for r in results:
        if not r.ok:
            continue
        for e in r.entries:
            votes.setdefault(e, set()).add(r.source.id)
            if r.source.confidence == "high":
                forced.add(e)
    for ib in inbox:
        for e in ib.iocs:
            votes.setdefault(e, set()).add(f"inbox:{ib.origin}")
            if ib.cls == "block":
                forced.add(e)

    dropped = {"allowlist": 0}
    allow_warn: List[str] = []
    lists: Dict[str, List[str]] = {name: [] for name in FEEDS}
    by_kind_level = {v: k for k, v in FEEDS.items()}
    for e, srcs in votes.items():
        if allow.blocks(e):
            dropped["allowlist"] += 1
            if e in forced and any(s.startswith("inbox:") for s in srcs):
                allow_warn.append(f"'{e.value}' injetado como block mas está na allowlist: ignorado")
            continue
        if e.kind in ("md5", "sha1", "sha256"):
            lists[by_kind_level[(e.kind, None)]].append(e.value)
            continue
        level = "block" if (e in forced or len(srcs) >= 2) else "monitor"
        lists[by_kind_level[(e.kind, level)]].append(e.value)

    for name, (kind, _lvl) in FEEDS.items():
        lists[name] = sorted(set(lists[name]), key=I.sort_key_ip) if kind == "ip" else sorted(set(lists[name]))
    return lists, {"dropped": dropped, "allow_warnings": allow_warn}


# ── Escrita, circuit breaker, relatório ───────────────────────────────────────────

def _read_lines(p: Path) -> List[str]:
    if not p.is_file():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]


def _write_if_changed(p: Path, text: str) -> bool:
    if p.is_file() and p.read_text(encoding="utf-8", errors="replace") == text:
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    return True


@dataclass
class BuildResult:
    rc: int = 0
    feeds: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    sources: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    changed: bool = False


def build(root: Path, today: Optional[date] = None, now: Optional[datetime] = None, fixtures: Optional[str] = None,
          allow_pending: bool = False, prune: bool = False, dry_run: bool = False) -> BuildResult:
    """Corre tudo. rc: 0 ok · 2 circuit breaker disparou (a lista anterior foi mantida)."""
    now = now or datetime.now(timezone.utc)
    today = today or now.date()
    cfg = load_config(root / "threatlists" / "config.toml")
    out = root / "threatlists" / "feeds"
    allow = load_allowlist(root, cfg)
    br = BuildResult()

    results: List[Result] = []
    for src in cfg["sources"]:
        row = {"id": src.id, "name": src.name, "kind": src.kind, "status": src.status, "license": src.license}
        if not src.enabled:
            br.sources.append({**row, "state": "desativada"})
            continue
        if src.status != "verified" and not allow_pending:
            br.sources.append({**row, "state": "ignorada (licença por confirmar)"})
            continue
        r = load(src, fixtures, cfg["policy"]["min_prefix_v4"])
        results.append(r)
        br.sources.append({**row, "state": "ok" if r.ok else "FALHOU", "entries": len(r.entries), "invalid": r.invalid,
                           "skipped_v6": r.skipped_v6, "error": r.error})
        if not r.ok:
            br.notes.append(f"fonte {src.id} falhou: {r.error}")

    inbox, inbox_notes = read_inbox(root, cfg, today, prune)
    br.notes += inbox_notes
    lists, info = classify(results, inbox, allow)
    br.notes += info["allow_warnings"]

    changes: Dict[str, Dict[str, Any]] = {}
    for name, (kind, level) in FEEDS.items():
        new = lists[name]
        prev = _read_lines(out / name)
        limit = int(cfg["limits"][name])
        tripped = ""
        if len(new) > limit:
            tripped = f"{len(new)} entradas acima do teto de {limit}"
        elif len(prev) >= int(cfg["breaker"]["min_previous"]):
            pct = abs(len(new) - len(prev)) * 100 / len(prev)
            if pct > float(cfg["breaker"]["max_change_pct"]):
                tripped = f"variação de {pct:.0f}% ({len(prev)} → {len(new)}) acima do limite de {cfg['breaker']['max_change_pct']}%"
        text = "\n".join(new) + ("\n" if new else "")
        added = sorted(set(new) - set(prev))
        removed = sorted(set(prev) - set(new))
        row = {"count": len(new), "previous": len(prev), "added": len(added), "removed": len(removed),
               "sample_added": added[:10], "sample_removed": removed[:10], "sha256": hashlib.sha256(text.encode()).hexdigest()}
        if tripped:
            row.update(state="BLOQUEADA (circuit breaker)", reason=tripped, count=len(prev), sha256=hashlib.sha256(
                ("\n".join(prev) + ("\n" if prev else "")).encode()).hexdigest())
            br.rc = 2
            br.notes.append(f"{name}: {tripped}; a lista anterior foi mantida")
        else:
            row["state"] = "ok"
            if not dry_run and _write_if_changed(out / name, text):
                br.changed = True
            elif dry_run and text != ("\n".join(prev) + ("\n" if prev else "")):
                br.changed = True
        changes[name] = row
    br.feeds = changes

    if not dry_run:
        _write_outputs(root, cfg, br, inbox, info, now)
    return br


def _write_outputs(root: Path, cfg: Dict[str, Any], br: BuildResult, inbox: List[InboxEntry], info: Dict[str, Any], now: datetime) -> None:
    out = root / "threatlists" / "feeds"
    man_path = out / "manifest.json"
    prev_updated = None
    if man_path.is_file():
        try:
            prev_updated = json.loads(man_path.read_text(encoding="utf-8")).get("updated")
        except ValueError:
            pass
    updated = now.strftime("%Y-%m-%dT%H:%M:%SZ") if (br.changed or not prev_updated) else prev_updated
    manifest = {
        "updated": updated,
        "feeds": {n: {"count": r["count"], "sha256": r["sha256"]} for n, r in br.feeds.items()},
        "sources": {s["id"]: {"state": s["state"], "status": s["status"], "license": s["license"]} for s in br.sources},
        "inbox_files": len(inbox),
    }
    _write_if_changed(man_path, json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n")

    L: List[str] = ["# Listas de ameaças — último relatório", "", f"Atualizado: {updated}", ""]
    L += ["## Listas", "", "| Lista | Entradas | Antes | Entraram | Saíram | Estado |", "|---|---:|---:|---:|---:|---|"]
    for n, r in br.feeds.items():
        L.append(f"| {n} | {r['count']} | {r['previous']} | +{r['added']} | -{r['removed']} | {r['state']} |")
    L += ["", "## Fontes", "", "| Fonte | Tipo | Estado | Entradas válidas | Inválidas | Licença |", "|---|---|---|---:|---:|---|"]
    for s in br.sources:
        L.append(f"| {s['name']} | {s['kind']} | {s['state']} | {s.get('entries', '')} | {s.get('invalid', '')} | {s['license'] or '—'} |")
    L += ["", f"Inbox: {len(inbox)} ficheiro(s) ativo(s). Entradas na allowlist ignoradas: {info['dropped']['allowlist']}.", ""]
    if br.notes:
        L += ["## Avisos", ""] + [f"- {n}" for n in br.notes] + [""]
    for n, r in br.feeds.items():
        if r["sample_added"] or r["sample_removed"]:
            L += [f"### {n}", ""]
            if r["sample_added"]:
                L.append("Entraram (amostra): " + ", ".join(f"`{x}`" for x in r["sample_added"]))
            if r["sample_removed"]:
                L.append("Saíram (amostra): " + ", ".join(f"`{x}`" for x in r["sample_removed"]))
            L.append("")
    report = root / "threatlists" / "reports" / "latest.md"
    if br.changed or not report.is_file():      # senão a execução seguinte (sem mudanças) reescreveria "+0/-0" e geraria outro commit
        _write_if_changed(report, "\n".join(L) + "\n")
