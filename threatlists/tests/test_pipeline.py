import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tl import ioc as I  # noqa: E402
from tl import sources as S  # noqa: E402
from tl.pipeline import build, read_inbox, load_config  # noqa: E402

CONFIG = """
[policy]
min_prefix_v4 = 16
inbox_default_ttl_days = 30
inbox_default_class = "block"
[breaker]
min_previous = 5
max_change_pct = 50
[limits]
"ip-block.txt" = 1000
"ip-monitor.txt" = 1000
"domain-block.txt" = 1000
"domain-monitor.txt" = 1000
"hash-md5.txt" = 1000
"hash-sha1.txt" = 1000
"hash-sha256.txt" = 1000
[allowlist]
files = ["threatlists/allowlist.txt"]
external = ["IP_Exceptions"]

[[source]]
id = "c2"
name = "C2 feed"
url = "https://x/c2.txt"
kind = "ip"
format = "lines"
confidence = "high"
status = "verified"
license = "CC0"
min_entries = 1

[[source]]
id = "noisy-a"
name = "Noisy A"
url = "https://x/a.txt"
kind = "ip"
format = "lines"
confidence = "low"
status = "verified"
min_entries = 1

[[source]]
id = "noisy-b"
name = "Noisy B"
url = "https://x/b.txt"
kind = "ip"
format = "lines"
confidence = "low"
status = "verified"
min_entries = 1

[[source]]
id = "doms"
name = "Hosts"
url = "https://x/h.txt"
kind = "domain"
format = "hosts"
confidence = "normal"
status = "verified"
min_entries = 1

[[source]]
id = "hashes"
name = "Hashes"
url = "https://x/s.txt"
kind = "sha256"
format = "lines"
status = "verified"
min_entries = 1

[[source]]
id = "tf"
name = "ThreatFox"
url = "https://x/tf.csv"
kind = "ip"
format = "csv"
column = 2
min_conf_column = 3
min_conf = 75
confidence = "low"
status = "verified"
min_entries = 1

[[source]]
id = "pendente"
name = "Licença por confirmar"
url = "https://x/p.txt"
kind = "ip"
format = "lines"
status = "pending"
min_entries = 1
"""
SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FIX = {
    "c2": "# c2\n45.33.32.156\n185.220.101.1\n8.8.8.8\n10.0.0.5\n",
    "noisy-a": "1.2.3.4\n185.220.101.1\n99.99.99.99\n; comentario\n",
    "noisy-b": "1.2.3.4\n77.88.99.11\n",
    "doms": "# hosts\n127.0.0.1\tevil.example.com\n0.0.0.0 bad.test.org\n127.0.0.1 fortinet.com\n127.0.0.1 support.fortinet.com\n",
    "hashes": f"# h\n{SHA}\nnotahash\n",
    "tf": '# comentario\n"2026-01-01","1","66.66.66.66:443","90"\n"2026-01-01","2","67.67.67.67:80","40"\n',
    "pendente": "200.200.200.200\n",
}


def _rm(func, path, _exc):
    os.chmod(path, 0o700)
    func(path)


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="tl-"))
        self.addCleanup(shutil.rmtree, self.root, onerror=_rm)
        (self.root / "threatlists").mkdir()
        (self.root / "threatlists" / "config.toml").write_text(CONFIG, encoding="utf-8")
        (self.root / "threatlists" / "allowlist.txt").write_text("8.8.8.8\nfortinet.com\n", encoding="utf-8")
        (self.root / "IP_Exceptions").write_text("77.88.99.11\r\n", encoding="utf-8")
        self.fx = self.root / "fx"
        self.fx.mkdir()
        for k, v in FIX.items():
            (self.fx / f"{k}.txt").write_text(v, encoding="utf-8")
        self.now = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)

    def run_build(self, **kw):
        kw.setdefault("now", self.now)
        kw.setdefault("fixtures", str(self.fx))
        return build(self.root, **kw)

    def feed(self, name):
        p = self.root / "threatlists" / "feeds" / name
        return p.read_text(encoding="utf-8").split() if p.exists() else None


class Classificacao(Base):
    def test_listas(self):
        r = self.run_build()
        self.assertEqual(r.rc, 0)
        # block: fonte 'high' (45.33.32.156, 185.220.101.1) ou 2 fontes (1.2.3.4); monitor: 1 fonte 'low'
        self.assertEqual(self.feed("ip-block.txt"), ["1.2.3.4", "45.33.32.156", "185.220.101.1"])
        self.assertEqual(self.feed("ip-monitor.txt"), ["66.66.66.66", "99.99.99.99"])
        self.assertEqual(self.feed("domain-block.txt"), [])
        self.assertEqual(self.feed("domain-monitor.txt"), ["bad.test.org", "evil.example.com"])      # fortinet.com e subdomínios: allowlist
        self.assertEqual(self.feed("hash-sha256.txt"), [SHA])

    def test_allowlist_e_externas(self):
        self.run_build()
        everything = " ".join(sum((self.feed(n) or [] for n in ("ip-block.txt", "ip-monitor.txt", "domain-monitor.txt")), []))
        self.assertNotIn("8.8.8.8", everything)             # allowlist.txt
        self.assertNotIn("77.88.99.11", everything)         # IP_Exceptions (lista externa, só lida)
        self.assertNotIn("fortinet.com", everything)        # inclui subdomínios
        self.assertNotIn("10.0.0.5", everything)            # privado

    def test_fonte_pendente_nao_publica(self):
        r = self.run_build()
        self.assertNotIn("200.200.200.200", self.feed("ip-block.txt") + self.feed("ip-monitor.txt"))
        self.assertIn("ignorada", [s for s in r.sources if s["id"] == "pendente"][0]["state"])

    def test_allow_pending_so_com_flag(self):
        self.run_build(allow_pending=True)
        self.assertIn("200.200.200.200", self.feed("ip-monitor.txt"))

    def test_csv_com_filtro_de_confianca(self):
        self.run_build()
        mon = self.feed("ip-monitor.txt")
        self.assertIn("66.66.66.66", mon)
        self.assertNotIn("67.67.67.67", mon)                # confiança 40 < 75


class Determinismo(Base):
    def test_segunda_corrida_nao_altera_nada(self):
        a = self.run_build()
        self.assertTrue(a.changed)
        snap = {p.name: p.read_bytes() for p in (self.root / "threatlists" / "feeds").iterdir()}
        rep = (self.root / "threatlists" / "reports" / "latest.md").read_bytes()
        b = self.run_build(now=datetime(2026, 10, 12, 18, 0, tzinfo=timezone.utc))   # 6 h depois
        self.assertFalse(b.changed)
        self.assertEqual(snap, {p.name: p.read_bytes() for p in (self.root / "threatlists" / "feeds").iterdir()})   # nem o manifest
        self.assertEqual(rep, (self.root / "threatlists" / "reports" / "latest.md").read_bytes())

    def test_ficheiros_so_com_lf(self):
        self.run_build()
        for p in (self.root / "threatlists" / "feeds").glob("*.txt"):
            self.assertNotIn(b"\r", p.read_bytes())

    def test_dry_run_nao_escreve(self):
        r = self.run_build(dry_run=True)
        self.assertTrue(r.changed)
        self.assertFalse((self.root / "threatlists" / "feeds").exists())


class Falhas(Base):
    def test_fonte_em_falta_nao_derruba_as_outras(self):
        (self.fx / "noisy-a.txt").unlink()
        r = self.run_build()
        self.assertEqual(r.rc, 0)
        self.assertEqual([s["state"] for s in r.sources if s["id"] == "noisy-a"], ["FALHOU"])
        self.assertIn("45.33.32.156", self.feed("ip-block.txt"))

    def test_resposta_html_ou_vazia_e_falha(self):
        (self.fx / "c2.txt").write_text("# so comentarios\n", encoding="utf-8")        # 0 entradas válidas < min_entries
        r = self.run_build()
        self.assertEqual([s["state"] for s in r.sources if s["id"] == "c2"], ["FALHOU"])

    def test_html_rejeitado_no_fetch(self):
        class R:                    # simula urlopen devolvendo uma página de erro
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def read(s, n): return b"<html><body>429 Too Many Requests</body></html>"
        import urllib.request
        orig = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **k: R()
        try:
            with self.assertRaises(S.FetchError):
                S.fetch("https://x/y")
        finally:
            urllib.request.urlopen = orig

    def test_so_http_s(self):
        with self.assertRaises(S.FetchError):
            S.fetch("file:///etc/passwd")
        with self.assertRaises(S.FetchError):
            S.fetch("ftp://x/y")


class Breaker(Base):
    def _seed(self, n):
        d = self.root / "threatlists" / "feeds"
        d.mkdir(parents=True)
        (d / "ip-block.txt").write_text("".join(f"198.51.{i // 250}.{i % 250 + 1}\n" for i in range(n)), encoding="utf-8")
        return d / "ip-block.txt"

    def test_queda_brusca_mantem_a_lista_anterior(self):
        p = self._seed(20)
        before = p.read_text(encoding="utf-8")
        r = self.run_build()                                  # passa a 3 entradas: -85 %
        self.assertEqual(r.rc, 2)
        self.assertEqual(p.read_text(encoding="utf-8"), before)
        self.assertIn("BLOQUEADA", r.feeds["ip-block.txt"]["state"])
        self.assertEqual(r.feeds["ip-block.txt"]["count"], 20)
        self.assertEqual(r.feeds["ip-monitor.txt"]["state"], "ok")     # as outras listas seguem

    def test_variacao_pequena_passa(self):
        p = self._seed(4)                                     # abaixo de min_previous: sem verificação
        self.assertEqual(self.run_build().rc, 0)

    def test_teto(self):
        cfg = (self.root / "threatlists" / "config.toml")
        cfg.write_text(cfg.read_text(encoding="utf-8").replace('"ip-block.txt" = 1000', '"ip-block.txt" = 2'), encoding="utf-8")
        r = self.run_build()
        self.assertEqual(r.rc, 2)
        self.assertIn("teto", r.feeds["ip-block.txt"]["reason"])
        self.assertIsNone(self.feed("ip-block.txt"))          # nunca existiu e não foi escrita


class Inbox(Base):
    def _inbox(self, name, text, origin="CNCS"):
        d = self.root / "threatlists" / "inbox" / origin.lower()
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(text, encoding="utf-8")
        return d / name

    def test_entra_como_block_e_ofuscado(self):
        self._inbox("a.txt", "# origin: CNCS\n# ref: CNCS-1\n# class: block\n# added: 2026-10-10\n# expires: 2026-11-10\n"
                             "5.5.5.5\nhxxp://evil-cncs[.]pt/x\n")
        self.run_build()
        self.assertIn("5.5.5.5", self.feed("ip-block.txt"))
        self.assertIn("evil-cncs.pt", self.feed("domain-block.txt"))

    def test_monitor_e_default_por_config(self):
        self._inbox("a.txt", "# added: 2026-10-10\n# class: monitor\n6.6.6.6\n")
        self.run_build()
        self.assertIn("6.6.6.6", self.feed("ip-monitor.txt"))
        self.assertNotIn("6.6.6.6", self.feed("ip-block.txt"))

    def test_expirado_e_ignorado_e_apagado_com_prune(self):
        p = self._inbox("old.txt", "# added: 2026-01-01\n# expires: 2026-02-01\n7.7.7.7\n")
        r = self.run_build()
        self.assertNotIn("7.7.7.7", self.feed("ip-block.txt") + self.feed("ip-monitor.txt"))
        self.assertTrue(p.exists())
        self.run_build(prune=True)
        self.assertFalse(p.exists())

    def test_ttl_por_omissao(self):
        self._inbox("a.txt", "# added: 2026-09-01\n8.7.7.7\n")             # +30 d = 2026-10-01 < hoje
        self.run_build()
        self.assertNotIn("8.7.7.7", self.feed("ip-block.txt") + self.feed("ip-monitor.txt"))

    def test_sem_added_e_ignorado_com_aviso(self):
        self._inbox("a.txt", "9.9.9.10\n")
        r = self.run_build()
        self.assertTrue(any("falta '# added" in n for n in r.notes))

    def test_class_invalida_ignorada(self):
        self._inbox("a.txt", "# added: 2026-10-10\n# class: allow\n9.9.9.11\n")
        r = self.run_build()
        self.assertTrue(any("class" in n for n in r.notes))
        self.assertNotIn("9.9.9.11", self.feed("ip-block.txt") + self.feed("ip-monitor.txt"))

    def test_injetado_como_block_mas_na_allowlist_e_ignorado_com_aviso(self):
        self._inbox("a.txt", "# added: 2026-10-10\n# class: block\n8.8.8.8\n")
        r = self.run_build()
        self.assertNotIn("8.8.8.8", self.feed("ip-block.txt"))
        self.assertTrue(any("allowlist" in n for n in r.notes))

    def test_privados_recusados_no_inbox(self):
        self._inbox("a.txt", "# added: 2026-10-10\n10.1.1.1\n8.0.0.0/8\n")
        r = self.run_build()
        self.assertTrue(any("10.1.1.1" in n for n in r.notes))
        self.assertTrue(any("8.0.0.0/8" in n for n in r.notes))

    def test_duas_fontes_promovem_para_block(self):
        self._inbox("a.txt", "# added: 2026-10-10\n# class: monitor\n99.99.99.99\n")     # noisy-a também tem 99.99.99.99
        self.run_build()
        self.assertIn("99.99.99.99", self.feed("ip-block.txt"))


class Inject(Base):
    def run_inject(self, text, *args, **env):
        e = {**os.environ, "IOC_TEXT": text}
        return subprocess.run([sys.executable, str(HERE.parent / "inject.py"), "--root", str(self.root),
                               "--now", "2026-10-12T12:00:00", *args], capture_output=True, text=True, env=e)

    def test_escreve_ficheiro_com_cabecalho(self):
        p = self.run_inject("Aviso: 5.5.5.5 e evil[.]pt e 10.0.0.1 e 8.8.8.8", "--origin", "CNCS", "--ref", "CNCS-2026-9", "--days", "10")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        f = next((self.root / "threatlists" / "inbox" / "cncs").glob("*.txt"))
        lines = f.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[:5], ["# origin: CNCS", "# ref: CNCS-2026-9", "# class: block", "# added: 2026-10-12", "# expires: 2026-10-22"])
        self.assertEqual(sorted(lines[5:]), ["5.5.5.5", "evil.pt"])           # privado e allowlist ficam de fora
        self.assertIn("recusado: 10.0.0.1", p.stdout)

    def test_o_build_aceita_o_que_o_inject_escreve(self):
        self.run_inject("5.5.5.5", "--origin", "CNCS", "--days", "400")      # fora do intervalo
        self.assertEqual(len(list((self.root / "threatlists").glob("inbox"))), 0)
        p = self.run_inject("5.5.5.5", "--origin", "CNCS", "--days", "30")
        self.assertEqual(p.returncode, 0)
        r = self.run_build()
        self.assertIn("5.5.5.5", self.feed("ip-block.txt"))

    def test_nada_valido_nao_escreve(self):
        p = self.run_inject("so texto 10.0.0.1 e 8.8.8.8")
        self.assertEqual(p.returncode, 3)
        self.assertFalse((self.root / "threatlists" / "inbox").exists())

    def test_ref_com_quebra_de_linha_nao_injeta_cabecalhos(self):
        p = self.run_inject("5.5.5.5", "--ref", "x\n# class: monitor\n# expires: 2099-01-01", "--origin", "CNCS\n# class: monitor")
        self.assertEqual(p.returncode, 0, p.stderr)
        f = next((self.root / "threatlists" / "inbox").rglob("*.txt"))
        text = f.read_text(encoding="utf-8")
        self.assertEqual(text.count("# class:"), 1)
        self.assertEqual(text.count("# expires:"), 1)
        self.assertIn("# class: block", text)

    def test_texto_enorme_e_recusado(self):
        p = self.run_inject("a" * 600_000)
        self.assertEqual(p.returncode, 1)


class Config(unittest.TestCase):
    def test_config_real_do_repositorio_carrega(self):
        cfg = load_config(HERE.parent / "config.toml")
        ids = [s.id for s in cfg["sources"]]
        self.assertEqual(len(ids), len(set(ids)))
        for s in cfg["sources"]:
            self.assertIn(s.status, ("verified", "pending"))
            if s.status == "verified":
                self.assertTrue(s.license, f"{s.id}: fonte verificada sem licença registada")
                self.assertTrue(s.terms_url, f"{s.id}: fonte verificada sem terms_url")
        for name in cfg["limits"]:
            self.assertTrue(name.endswith(".txt"))

    def test_campo_desconhecido_e_erro(self):
        with self.assertRaises(ValueError):
            S.Source.from_dict({"id": "x", "name": "x", "url": "https://x", "kind": "ip", "format": "lines", "typo": 1})


if __name__ == "__main__":
    unittest.main()
