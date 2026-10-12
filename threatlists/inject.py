#!/usr/bin/env python3
"""Injeta IOCs (aviso do CNCS|CERT.PT, lista manual) no inbox. Uso (é o que o workflow corre; o texto vem por variável de ambiente,
nunca interpolado no shell):

  IOC_TEXT="..." python threatlists/inject.py --origin CNCS --ref "CNCS-2026-123" --days 30 --class block

Aceita texto livre com ofuscação ("hxxp", "1[.]2[.]3[.]4"). Recusa IPs privados, prefixos demasiado largos e o que está na
allowlist. Código de saída: 0 escreveu · 3 não havia IOCs válidos (nada escrito).
"""
import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tl import ioc as I  # noqa: E402
from tl.pipeline import load_allowlist, load_config  # noqa: E402


def slug(s: str, default: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", (s or "").strip()).strip("-").lower()[:40]
    return s or default


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--origin", default="manual")
    ap.add_argument("--ref", default="")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--class", dest="cls", choices=("block", "monitor"), default="block")
    ap.add_argument("--text-env", default="IOC_TEXT", help="variável de ambiente com o texto")
    ap.add_argument("--file", help="ler o texto deste ficheiro em vez da variável de ambiente")
    ap.add_argument("--now", help="(testes) AAAA-MM-DDTHH:MM:SS")
    a = ap.parse_args()

    if not 1 <= a.days <= 365:
        print("ERRO: --days tem de estar entre 1 e 365")
        return 1
    text = Path(a.file).read_text(encoding="utf-8", errors="replace") if a.file else os.environ.get(a.text_env, "")
    if len(text) > 500_000:
        print("ERRO: texto demasiado grande (máx. 500 000 carateres)")
        return 1

    root = Path(a.root)
    cfg = load_config(root / "threatlists" / "config.toml")
    allow = load_allowlist(root, cfg)
    ex = I.extract(text, cfg["policy"]["min_prefix_v4"])
    keep = [i for i in ex["iocs"] if not allow.blocks(i)]           # type: ignore[union-attr]
    skipped_allow = len(ex["iocs"]) - len(keep)                      # type: ignore[arg-type]

    print(f"Extraídos: {len(ex['iocs'])} · na allowlist (ignorados): {skipped_allow} · IPv6 ignorados: {ex['skipped_v6']}")   # type: ignore[arg-type]
    for val, why in ex["rejected"]:                                  # type: ignore[union-attr]
        print(f"  recusado: {val} ({why})")
    if not keep:
        print("Nada para injetar.")
        return 3

    now = datetime.fromisoformat(a.now) if a.now else datetime.now(timezone.utc)
    origin = slug(a.origin, "manual")
    ref = re.sub(r"[^A-Za-z0-9 _./-]+", "", a.ref)[:80].strip()     # uma só linha, sem carateres que partam o cabeçalho
    d = root / "threatlists" / "inbox" / origin
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{now:%Y%m%d-%H%M%S}-{slug(ref, 'sem-ref')}.txt"
    origin_label = re.sub(r"[^A-Za-z0-9 _.-]+", "", a.origin).strip()[:40] or origin     # uma só linha, sem carateres especiais
    lines = [f"# origin: {origin_label}",
             f"# ref: {ref}", f"# class: {a.cls}", f"# added: {now:%Y-%m-%d}", f"# expires: {(now + timedelta(days=a.days)):%Y-%m-%d}"]
    lines += [i.value for i in keep]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Escrito {path.relative_to(root).as_posix()} com {len(keep)} entradas ({a.cls}, válidas {a.days} dias).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
