#!/usr/bin/env python3
"""Gera as listas em threatlists/feeds/. Uso:

  python threatlists/build.py                      # produção (o que o GitHub Actions corre)
  python threatlists/build.py --dry-run            # não escreve nada, só mostra o que mudaria
  python threatlists/build.py --allow-pending      # inclui fontes com licença por confirmar (SÓ para testes locais; não fazer commit)
  python threatlists/build.py --fixtures DIR       # lê DIR/<id-da-fonte>.txt em vez de descarregar (testes)
  python threatlists/build.py --prune              # apaga do inbox os ficheiros expirados

Código de saída: 0 ok · 2 circuit breaker disparou (a lista anterior foi mantida e o job deve falhar).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tl.pipeline import build  # noqa: E402


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):          # consolas do Windows (cp1252) rebentariam com os acentos
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent), help="raiz do repositório")
    ap.add_argument("--fixtures")
    ap.add_argument("--allow-pending", action="store_true")
    ap.add_argument("--prune", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    r = build(Path(a.root), fixtures=a.fixtures, allow_pending=a.allow_pending, prune=a.prune, dry_run=a.dry_run)

    print("Fontes:")
    for s in r.sources:
        extra = f" · {s['entries']} válidas, {s['invalid']} inválidas" if "entries" in s else ""
        print(f"  {s['id']:<16} {s['state']}{extra}")
    print("Listas:")
    for n, f in r.feeds.items():
        print(f"  {n:<20} {f['count']:>6}  (antes {f['previous']}, +{f['added']} -{f['removed']})  {f['state']}")
    for n in r.notes:
        print("AVISO:", n)
    print("Alterado:" , "sim" if r.changed else "não", "| dry-run" if a.dry_run else "")
    return r.rc


if __name__ == "__main__":
    sys.exit(main())
