# threatlists

Listas de IPs, domínios e hashes geradas automaticamente a partir de fontes abertas e de entradas injetadas (CNCS|CERT.PT, manuais),
para consumo por FortiGate (External Connector) e Palo Alto (EDL). **Não altera nenhuma das listas da raiz do repositório**
(`ipblock.txt`, `domainsblock.txt`, …): tudo vive em `threatlists/`. Só stdlib, Python ≥ 3.11.

## Listas (`feeds/`)

URL base: `https://raw.githubusercontent.com/pfsyscon/fortigate/main/threatlists/feeds/`

| Ficheiro | Conteúdo | Usar como |
|---|---|---|
| `ip-block.txt` | IPv4/CIDR: fonte de confiança alta, **ou** 2+ fontes, **ou** injetado como `block` | bloquear |
| `ip-monitor.txt` | IPv4/CIDR vistos numa só fonte de confiança normal/baixa | só registar |
| `domain-block.txt` / `domain-monitor.txt` | idem, para domínios | bloquear / registar |
| `hash-md5.txt`, `hash-sha1.txt`, `hash-sha256.txt` | hashes de malware | AV profile |
| `manifest.json` | contagens e sha256 de cada lista, estado das fontes | |

Um IOC por linha, LF, sem comentários nem cabeçalhos (os firewalls aceitam o ficheiro tal como está).
`reports/latest.md` diz o que entrou e saiu em cada atualização e os avisos.

FortiGate (confirmar a sintaxe na versão do FortiOS):

```
config system external-resource
    edit "TL-IP-Block"
        set type address
        set resource "https://raw.githubusercontent.com/pfsyscon/fortigate/main/threatlists/feeds/ip-block.txt"
        set refresh-rate 60
    next
end
```

**Não ligar a nenhuma política deny sem antes ver `ip-monitor`/`reports` em modo de registo.**

## Como funciona

`.github/workflows/threatlists-build.yml` corre de 6 em 6 h (e quando o inbox, a allowlist ou a config mudam):
testes → (injeção opcional) → `build.py` → commit só se algo mudou.

1. **Fontes** (`config.toml`, `[[source]]`): descarrega, valida cada valor (IP público, prefixo ≥ /16, domínio com TLD válido, hash com tamanho certo)
   e descarta o resto. Uma resposta HTML, vazia ou com poucas entradas válidas conta como falha dessa fonte (as outras seguem).
2. **Classificação:** `block` = fonte `confidence = "high"`, ou 2+ fontes concordam, ou injetado como `block`; senão `monitor`.
3. **Allowlist** (`allowlist.txt` + `IP_Exceptions`, `Microsoft_IPs`, `google-crawlers.txt` da raiz, só lidas): qualquer sobreposição descarta o IOC.
4. **Circuit breaker:** se uma lista variar mais de `max_change_pct` ou passar o teto de `[limits]`, **não se publica**, mantém-se a anterior,
   as outras listas seguem e o job falha (o GitHub avisa por e-mail).
5. Saída determinística: sem alterações não há commit.

## Licenças das fontes

O repositório é **público**, por isso só fontes com `status = "verified"` (licença confirmada) publicam.
Hoje só o Feodo Tracker (CC0). As restantes estão registadas com `status = "pending"` e não entram nas listas publicadas:

| Fonte | Situação |
|---|---|
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | "fair use"; uso comercial pode exigir subscrição → confirmar com a abuse.ch |
| blocklist.de | sem termos publicados |
| CINS Army | sem licença declarada; só HTTP |

Para passar uma fonte a publicada: confirmar os termos, preencher `license`/`terms_url` e mudar `status` para `"verified"` (há um teste que exige isto).
Para ver o que sairia com todas: `python threatlists/build.py --dry-run --allow-pending` (não escreve nada).

## Injeção do CNCS (e manual)

GitHub → Actions → **Threatlists build** → *Run workflow* → colar o texto do aviso em `inject_text`, indicar a referência e a validade.
Aceita texto livre e ofuscação (`hxxps://evil[.]pt`, `1[.]2[.]3[.]4`); recusa IPs privados, prefixos largos e o que está na allowlist.
Cria `inbox/<origem>/AAAAMMDD-HHMMSS-<ref>.txt`, que expira sozinho. Ver `inbox/README.md`.

Localmente: `IOC_TEXT="..." python threatlists/inject.py --origin CNCS --ref CNCS-2026-1 --days 30 --class block`.

## Testes

```
python -m unittest discover -s threatlists/tests
```

Offline: as fontes são simuladas com ficheiros em `fx/`. Correm sempre antes de publicar.

## Notas

- Só IPv4 nesta fase (IPv6 é reconhecido e ignorado).
- O GitHub desativa workflows agendados após 60 dias sem atividade no repositório.
