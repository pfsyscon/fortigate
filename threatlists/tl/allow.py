"""Allowlist: o que NUNCA pode entrar numa lista de bloqueio (DNS públicos, CDNs, IPs dos clientes, ...)."""
from __future__ import annotations

import bisect
import ipaddress
import re
from typing import List, Tuple

from . import ioc as I


class Allowlist:
    def __init__(self) -> None:
        self._ranges: List[Tuple[int, int]] = []
        self._starts: List[int] = []
        self.domains: set = set()
        self.entries = 0

    def add_text(self, text: str) -> int:
        """Uma entrada por linha: IPv4, CIDR ou domínio (um domínio protege também os subdomínios). '#' começa um comentário."""
        n = 0
        for raw in (text or "").splitlines():
            line = re.split(r"\s*#", raw, maxsplit=1)[0].strip()
            if not line:
                continue
            tok = line.split()[0]
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if net.version == 4:
                    self._ranges.append((int(net.network_address), int(net.broadcast_address)))
                    n += 1
                continue
            d = I.normalize_domain(tok)
            if d:
                self.domains.add(d)
                n += 1
        self.entries += n
        self._merge()
        return n

    def _merge(self) -> None:
        merged: List[Tuple[int, int]] = []
        for a, b in sorted(self._ranges):
            if merged and a <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], b))
            else:
                merged.append((a, b))
        self._ranges = merged
        self._starts = [a for a, _ in merged]

    def blocks_ip(self, value: str) -> bool:
        """True se o IP/CIDR se sobrepõe a qualquer entrada da allowlist."""
        net = ipaddress.ip_network(value, strict=False)
        lo, hi = int(net.network_address), int(net.broadcast_address)
        i = bisect.bisect_right(self._starts, hi) - 1      # último intervalo que começa antes do fim da rede
        return i >= 0 and self._ranges[i][1] >= lo

    def blocks_domain(self, value: str) -> bool:
        parts = value.split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts) - 1))

    def blocks(self, i: I.IOC) -> bool:
        if i.kind == "ip":
            return self.blocks_ip(i.value)
        if i.kind == "domain":
            return self.blocks_domain(i.value)
        return False
