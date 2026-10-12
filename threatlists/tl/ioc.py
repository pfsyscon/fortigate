"""Extração e normalização de IOCs (IPv4, CIDR, domínios, hashes). Só stdlib.

Duas portas de entrada:
  - normalize_*()  : um valor já isolado (feeds estruturados). Devolve o valor canónico ou None.
  - extract()      : texto livre (aviso do CNCS colado, Excel convertido) com ofuscação ("hxxp", "[.]").

Regras de segurança aplicadas a TUDO o que entra numa lista de bloqueio:
  - IPv4 só se for endereço público (sem RFC1918, loopback, link-local, multicast, reservado, CGNAT);
  - redes mais largas que min_prefix (por omissão /16) são recusadas: um prefixo enorme num feed é quase sempre um erro;
  - domínios têm de ter pelo menos 2 etiquetas e um TLD alfabético (ou xn--); nomes reservados (.local, .lan, ...) são recusados.
IPv6 é reconhecido e ignorado (contado como "skipped_v6"): as listas desta fase são só IPv4.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

DEFAULT_MIN_PREFIX_V4 = 16

KINDS = ("ip", "domain", "md5", "sha1", "sha256")
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}

_RESERVED_TLDS = {"local", "localhost", "lan", "internal", "intranet", "corp", "home", "test", "example", "invalid", "arpa", "onion"}
# Extensões de ficheiro que o texto livre confunde com domínios ("bin.sh", "relatorio.pdf")
_FILE_EXT = {
    "exe", "dll", "sh", "bat", "cmd", "ps1", "vbs", "js", "py", "pl", "jar", "msi", "scr", "lnk", "iso", "img", "bin", "dat",
    "txt", "log", "csv", "xls", "xlsx", "doc", "docx", "ppt", "pptx", "pdf", "rtf", "zip", "rar", "gz", "tar", "7z",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "json", "xml", "yml", "yaml", "ini", "cfg", "conf", "tmp", "bak",
}
_LABEL_RE = re.compile(r"^(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")


@dataclass(frozen=True, order=True)
class IOC:
    kind: str       # ip | domain | md5 | sha1 | sha256
    value: str      # forma canónica


# ── Valores isolados ────────────────────────────────────────────────────────────

def normalize_ip(token: str, min_prefix: int = DEFAULT_MIN_PREFIX_V4) -> Optional[str]:
    """IPv4 ou CIDR público → forma canónica ('1.2.3.4' ou '1.2.3.0/24'). None se recusado (incl. IPv6, ver is_ipv6)."""
    t = (token or "").strip()
    if not t or ":" in t:
        return None
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None
    if net.version != 4 or not net.is_global:
        return None
    # is_global deixa passar multicast (224/4); recusar explicitamente tudo o que não é unicast público
    if net.is_multicast or net.is_reserved or net.is_unspecified or net.is_loopback or net.is_link_local or net.is_private:
        return None
    if net.prefixlen < min_prefix:
        return None
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def is_ipv6(token: str) -> bool:
    t = (token or "").strip().strip("[]")
    try:
        ipaddress.IPv6Network(t, strict=False)
        return True
    except ValueError:
        return False


def normalize_domain(token: str) -> Optional[str]:
    t = (token or "").strip().lower().rstrip(".")
    if not t or len(t) > 253 or "." not in t:
        return None
    labels = t.split(".")
    if not all(_LABEL_RE.match(l) for l in labels):
        return None
    tld = labels[-1]
    if not _TLD_RE.match(tld) or tld in _RESERVED_TLDS:
        return None
    return t


def normalize_hash(token: str) -> Optional[IOC]:
    t = (token or "").strip().lower()
    kind = _HASH_LEN.get(len(t))
    if kind and re.fullmatch(r"[0-9a-f]+", t):
        return IOC(kind, t)
    return None


def host_of(url_or_host: str) -> str:
    """'http://1.2.3.4:8080/x' → '1.2.3.4'; 'evil.com:443' → 'evil.com'; '1.2.3.4:80' → '1.2.3.4'."""
    t = (url_or_host or "").strip()
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = re.split(r"[/?#]", t, maxsplit=1)[0]
    t = t.rsplit("@", 1)[-1]
    if t.count(":") == 1:                      # host:porto (IPv6 não é tratado aqui)
        t = t.split(":", 1)[0]
    return t.strip("[]")


def normalize(kind: str, token: str, min_prefix: int = DEFAULT_MIN_PREFIX_V4) -> Optional[IOC]:
    """Valida um token isolado para o tipo pedido."""
    if kind == "ip":
        is_cidr = "/" in token and "://" not in token
        v = normalize_ip(token, min_prefix) if is_cidr else normalize_ip(host_of(token), min_prefix)
        return IOC("ip", v) if v else None
    if kind == "domain":
        v = normalize_domain(host_of(token))
        return IOC("domain", v) if v else None
    if kind in ("md5", "sha1", "sha256"):
        h = normalize_hash(token)
        return h if h and h.kind == kind else None
    raise ValueError(f"tipo desconhecido: {kind}")


# ── Texto livre ──────────────────────────────────────────────────────────────────

_DEFANG = [
    (re.compile(r"\bhxxp(s?)\b", re.I), r"http\1"),
    (re.compile(r"\bfxp(s?)\b", re.I), r"ftp\1"),
    (re.compile(r"\[\s*://\s*\]|\[:\]//|\(://\)"), "://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\(\s*at\s*\)|\[\s*at\s*\]", re.I), "@"),
    (re.compile(r"\\\."), "."),
]
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)]+", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.]*\d)")
_DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9._-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}(?![A-Za-z0-9-])")
_HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")


def defang(text: str) -> str:
    for rx, repl in _DEFANG:
        text = rx.sub(repl, text)
    return text


def extract(text: str, min_prefix: int = DEFAULT_MIN_PREFIX_V4) -> Dict[str, object]:
    """Extrai IOCs de texto livre.

    Devolve {"iocs": [IOC...] (únicos, ordenados), "rejected": [(valor, motivo)...], "skipped_v6": int}.
    'rejected' ajuda a revisão: mostra o que parecia um IOC mas foi recusado (IP privado, prefixo largo, ficheiro...).
    """
    text = defang(text or "")
    found: Dict[IOC, None] = {}
    rejected: List[tuple] = []
    skipped_v6 = 0

    def add_ip(tok: str) -> None:
        v = normalize_ip(tok, min_prefix)
        if v:
            found[IOC("ip", v)] = None
            return
        try:
            net = ipaddress.ip_network(tok, strict=False)
            rejected.append((tok, "IP não público" if not net.is_global else f"prefixo /{net.prefixlen} demasiado largo"))
        except ValueError:
            rejected.append((tok, "IP inválido"))

    def add_domain(tok: str) -> None:
        v = normalize_domain(tok)
        tld = tok.rsplit(".", 1)[-1].lower()
        if v and tld not in _FILE_EXT:
            found[IOC("domain", v)] = None
        elif tld in _FILE_EXT:
            rejected.append((tok, "parece um ficheiro"))
        else:
            rejected.append((tok, "domínio inválido"))

    for h in _HASH_RE.findall(text):
        i = normalize_hash(h)
        if i:
            found[i] = None
    text_wo_hash = _HASH_RE.sub(" ", text)

    for u in _URL_RE.findall(text_wo_hash):
        host = host_of(u)
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            add_ip(host)
        elif is_ipv6(host):
            skipped_v6 += 1
        else:
            add_domain(host)
    rest = _URL_RE.sub(" ", text_wo_hash)

    for tok in _IPV4_RE.findall(rest):
        add_ip(tok)
    rest = _IPV4_RE.sub(" ", rest)
    for tok in _DOMAIN_RE.findall(rest):
        add_domain(tok)

    return {"iocs": sorted(found), "rejected": rejected, "skipped_v6": skipped_v6}


def sort_key_ip(value: str):
    net = ipaddress.ip_network(value, strict=False)
    return (int(net.network_address), net.prefixlen)


def group(iocs: Iterable[IOC]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {k: [] for k in KINDS}
    for i in iocs:
        out[i.kind].append(i.value)
    return out
