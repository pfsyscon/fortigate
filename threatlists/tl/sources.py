"""Registo de fontes: descarregar e converter cada formato numa lista de IOCs validados. Só stdlib."""
from __future__ import annotations

import csv
import io
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import ioc as I

USER_AGENT = "threatlists-build (+https://github.com/pfsyscon/fortigate)"
MAX_BYTES = 25 * 1024 * 1024


@dataclass
class Source:
    id: str
    name: str
    url: str
    kind: str                         # ip | domain | md5 | sha1 | sha256
    format: str                       # lines | hosts | csv | urls
    confidence: str = "normal"        # high = bloqueia sozinha; normal/low = precisam de 2+ fontes
    status: str = "pending"           # verified = licença confirmada, pode ser publicada; pending = só em testes locais
    license: str = ""
    terms_url: str = ""
    min_entries: int = 1              # abaixo disto a resposta é tratada como falha (formato mudou, página de erro...)
    enabled: bool = True
    column: int = 0                   # csv: coluna do valor
    min_conf_column: Optional[int] = None   # csv: coluna com a confiança do feed (0-100)
    min_conf: int = 0
    notes: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Source":
        known = {f for f in cls.__dataclass_fields__}
        extra = set(d) - known
        if extra:
            raise ValueError(f"fonte {d.get('id')}: campos desconhecidos {sorted(extra)}")
        s = cls(**d)
        if s.kind not in I.KINDS:
            raise ValueError(f"fonte {s.id}: kind inválido '{s.kind}'")
        if s.format not in PARSERS:
            raise ValueError(f"fonte {s.id}: format inválido '{s.format}'")
        if s.status not in ("verified", "pending"):
            raise ValueError(f"fonte {s.id}: status inválido '{s.status}'")
        if s.confidence not in ("high", "normal", "low"):
            raise ValueError(f"fonte {s.id}: confidence inválida '{s.confidence}'")
        return s


@dataclass
class Result:
    source: Source
    ok: bool = False
    error: str = ""
    entries: List[I.IOC] = field(default_factory=list)
    lines: int = 0
    invalid: int = 0
    skipped_v6: int = 0


class FetchError(Exception):
    pass


def fetch(url: str, timeout: int = 60, retries: int = 2) -> str:
    if not url.startswith(("https://", "http://")):
        raise FetchError("só http(s)")
    last: Exception = FetchError("sem tentativas")
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise FetchError(f"resposta acima de {MAX_BYTES // 1024 // 1024} MB")
            text = raw.decode("utf-8", errors="replace")
            head = text[:512].lstrip().lower()
            if head.startswith("<") or "<html" in head:
                raise FetchError("a resposta é HTML (página de erro ou bloqueio), não uma lista")
            return text
        except FetchError:
            raise
        except Exception as exc:        # rede, HTTP, timeout
            last = exc
    raise FetchError(f"{last.__class__.__name__}: {last}")


# ── Parsers: texto → tokens candidatos (o valor ainda não está validado) ─────────────

def _is_comment(line: str) -> bool:
    return line.startswith(("#", ";", "//"))


def _p_lines(src: Source, text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not _is_comment(line):
            out.append(line.split()[0].rstrip(",;"))
    return out


def _p_hosts(src: Source, text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or _is_comment(line):
            continue
        parts = line.split()
        if len(parts) >= 2:
            out.append(parts[1])
    return out


def _p_urls(src: Source, text: str) -> List[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not _is_comment(l.strip())]


def _p_csv(src: Source, text: str) -> List[str]:
    body = "\n".join(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#"))
    out = []
    for row in csv.reader(io.StringIO(body), skipinitialspace=True):
        if len(row) <= src.column:
            continue
        if src.min_conf_column is not None:
            try:
                if int(row[src.min_conf_column]) < src.min_conf:
                    continue
            except (ValueError, IndexError):
                continue
        out.append(row[src.column].strip())
    return out


PARSERS: Dict[str, Callable[[Source, str], List[str]]] = {"lines": _p_lines, "hosts": _p_hosts, "urls": _p_urls, "csv": _p_csv}


def parse(src: Source, text: str, min_prefix: int = I.DEFAULT_MIN_PREFIX_V4) -> Result:
    res = Result(source=src)
    tokens = PARSERS[src.format](src, text)
    res.lines = len(tokens)
    seen: Dict[I.IOC, None] = {}
    for tok in tokens:
        if src.kind == "ip" and I.is_ipv6(I.host_of(tok)):
            res.skipped_v6 += 1
            continue
        i = I.normalize(src.kind, tok, min_prefix)
        if i is None:
            res.invalid += 1
        else:
            seen[i] = None
    res.entries = list(seen)
    if len(res.entries) < src.min_entries:
        res.error = f"só {len(res.entries)} entradas válidas (mínimo {src.min_entries}): formato mudou ou resposta vazia"
        return res
    res.ok = True
    return res


def load(src: Source, fixtures_dir: Optional[str] = None, min_prefix: int = I.DEFAULT_MIN_PREFIX_V4) -> Result:
    """Descarrega (ou lê de fixtures_dir/<id>.txt nos testes) e converte. Nunca levanta: o erro fica em Result.error."""
    try:
        if fixtures_dir is not None:
            import os
            p = os.path.join(fixtures_dir, f"{src.id}.txt")
            if not os.path.exists(p):
                raise FetchError("sem fixture")
            with open(p, encoding="utf-8") as f:
                text = f.read()
        else:
            text = fetch(src.url)
    except FetchError as exc:
        return Result(source=src, error=str(exc))
    return parse(src, text, min_prefix)
