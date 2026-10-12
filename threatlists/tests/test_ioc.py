import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tl import ioc as I  # noqa: E402
from tl.allow import Allowlist  # noqa: E402

H_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
H_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
H_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class Normalizacao(unittest.TestCase):
    def test_ip_publico(self):
        self.assertEqual(I.normalize_ip("8.8.4.4"), "8.8.4.4")
        self.assertEqual(I.normalize_ip("91.240.118.0/24"), "91.240.118.0/24")
        self.assertEqual(I.normalize_ip("91.240.118.7/32"), "91.240.118.7")
        self.assertEqual(I.normalize_ip("91.240.118.7/24"), "91.240.118.0/24")       # bits de host normalizados

    def test_ip_recusado(self):
        for bad in ["10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "0.0.0.0",
                    "255.255.255.255", "1.2.3", "1.2.3.256", "010.1.1.1", "abc", "", "2001:db8::1", "1.2.3.4:80"]:
            self.assertIsNone(I.normalize_ip(bad), bad)

    def test_prefixo_largo_recusado(self):
        self.assertIsNone(I.normalize_ip("8.0.0.0/8"))
        self.assertIsNone(I.normalize_ip("91.0.0.0/15"))
        self.assertEqual(I.normalize_ip("91.240.0.0/16"), "91.240.0.0/16")
        self.assertEqual(I.normalize_ip("8.0.0.0/8", min_prefix=8), "8.0.0.0/8")

    def test_dominio(self):
        self.assertEqual(I.normalize_domain("Evil.Example.COM."), "evil.example.com")
        self.assertEqual(I.normalize_domain("xn--80ak6aa92e.com"), "xn--80ak6aa92e.com")
        for bad in ["localhost", "host.local", "a.lan", "-a.com", "a-.com", "a..com", "a b.com", "1.2.3.4", "a.c", "x" * 64 + ".com",
                    "foo.123", "under_score.com", "", "foo.test"]:
            self.assertIsNone(I.normalize_domain(bad), bad)

    def test_hash(self):
        self.assertEqual(I.normalize_hash(H_MD5.upper()), I.IOC("md5", H_MD5))
        self.assertEqual(I.normalize_hash(H_SHA1).kind, "sha1")
        self.assertEqual(I.normalize_hash(H_SHA256).kind, "sha256")
        self.assertIsNone(I.normalize_hash(H_MD5[:-1]))
        self.assertIsNone(I.normalize_hash("g" * 32))

    def test_host_of(self):
        self.assertEqual(I.host_of("http://1.2.3.4:8080/x?y"), "1.2.3.4")
        self.assertEqual(I.host_of("https://user:pw@evil.com/a"), "evil.com")
        self.assertEqual(I.host_of("evil.com:443"), "evil.com")
        self.assertEqual(I.host_of("1.2.3.4:80"), "1.2.3.4")

    def test_normalize_por_tipo(self):
        self.assertEqual(I.normalize("ip", "45.1.2.3:443"), I.IOC("ip", "45.1.2.3"))
        self.assertEqual(I.normalize("ip", "http://45.1.2.3:80/bin.sh"), I.IOC("ip", "45.1.2.3"))
        self.assertEqual(I.normalize("ip", "45.1.2.0/24"), I.IOC("ip", "45.1.2.0/24"))
        self.assertEqual(I.normalize("domain", "http://Evil.com/x"), I.IOC("domain", "evil.com"))
        self.assertIsNone(I.normalize("sha256", H_MD5))
        with self.assertRaises(ValueError):
            I.normalize("outro", "x")


class Extracao(unittest.TestCase):
    def values(self, text):
        return {(i.kind, i.value) for i in I.extract(text)["iocs"]}

    def test_ofuscacao(self):
        v = self.values("C2: hxxps://evil[.]example[.]com/a e 45[.]33[.]32[.]156 bem como 91(.)240(.)118(.)0/24 e foo(dot)org")
        self.assertEqual(v, {("domain", "evil.example.com"), ("ip", "45.33.32.156"), ("ip", "91.240.118.0/24"), ("domain", "foo.org")})

    def test_url_com_ip(self):
        self.assertEqual(self.values("http://45.33.32.156:8080/bin"), {("ip", "45.33.32.156")})

    def test_hashes_no_texto(self):
        v = self.values(f"MD5 {H_MD5}, SHA1 {H_SHA1}, SHA256 {H_SHA256}")
        self.assertEqual(v, {("md5", H_MD5), ("sha1", H_SHA1), ("sha256", H_SHA256)})

    def test_hash_nao_gera_ip_nem_dominio(self):
        self.assertEqual(self.values(H_SHA256), {("sha256", H_SHA256)})

    def test_recusados_com_motivo(self):
        r = I.extract("10.1.1.1 8.0.0.0/8 relatorio.pdf bin.sh 1.2.3.4.5")
        self.assertEqual(r["iocs"], [])
        motivos = dict(r["rejected"])
        self.assertIn("IP não público", motivos["10.1.1.1"])
        self.assertIn("largo", motivos["8.0.0.0/8"])
        self.assertIn("ficheiro", motivos["relatorio.pdf"])
        self.assertIn("ficheiro", motivos["bin.sh"])

    def test_email_devolve_o_dominio(self):
        self.assertEqual(self.values("contacto abuse@evil-corp[.]ru"), {("domain", "evil-corp.ru")})

    def test_ipv6_contado(self):
        r = I.extract("http://[2001:db8::1]/x")
        self.assertEqual(r["skipped_v6"], 1)
        self.assertEqual(r["iocs"], [])

    def test_unicos_e_ordenados(self):
        r = I.extract("1.2.3.4 1.2.3.4 evil.com evil.com")
        self.assertEqual(len(r["iocs"]), 2)

    def test_vazio_e_none(self):
        self.assertEqual(I.extract("")["iocs"], [])
        self.assertEqual(I.extract(None)["iocs"], [])

    def test_texto_hostil_nao_rebenta(self):
        I.extract("A" * 200000 + "." * 50000 + "\x00\x01" + "[" * 1000)


class Allow(unittest.TestCase):
    def setUp(self):
        self.al = Allowlist()
        self.al.add_text("8.8.8.8\n1.1.1.0/24  # cloudflare\nfortinet.com\n# comentário\n\n203.0.113.0/24\n")

    def test_ip_exato_e_rede(self):
        self.assertTrue(self.al.blocks_ip("8.8.8.8"))
        self.assertTrue(self.al.blocks_ip("1.1.1.9"))
        self.assertFalse(self.al.blocks_ip("8.8.8.9"))

    def test_sobreposicao_de_redes(self):
        self.assertTrue(self.al.blocks_ip("1.1.0.0/16"))          # a rede do feed contém a allowlist
        self.assertTrue(self.al.blocks_ip("203.0.113.128/25"))    # a rede do feed está dentro da allowlist
        self.assertFalse(self.al.blocks_ip("1.2.0.0/16"))

    def test_dominio_e_subdominios(self):
        self.assertTrue(self.al.blocks_domain("fortinet.com"))
        self.assertTrue(self.al.blocks_domain("support.fortinet.com"))
        self.assertTrue(self.al.blocks_domain("a.b.fortinet.com"))
        self.assertFalse(self.al.blocks_domain("notfortinet.com"))
        self.assertFalse(self.al.blocks_domain("fortinet.com.evil.ru"))
        self.assertFalse(self.al.blocks_domain("com"))

    def test_intervalos_fundidos(self):
        a = Allowlist()
        a.add_text("10.0.0.0/25\n10.0.0.128/25\n10.0.1.0/24")
        self.assertEqual(len(a._ranges), 1)
        self.assertTrue(a.blocks_ip("10.0.1.77"))
        self.assertFalse(a.blocks_ip("10.0.2.1"))

    def test_hashes_nunca_na_allowlist(self):
        self.assertFalse(self.al.blocks(I.IOC("sha256", H_SHA256)))


if __name__ == "__main__":
    unittest.main()
