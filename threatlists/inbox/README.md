# Inbox

Entradas injetadas à mão (avisos do CNCS|CERT.PT, listas manuais). Um ficheiro `.txt` por injeção, em `inbox/<origem>/`.
Não se editam à mão: usa o workflow **Threatlists build → Run workflow** (campo `inject_text`) ou `python threatlists/inject.py`.

Formato:

```
# origin: CNCS
# ref: CNCS-2026-123
# class: block          (block | monitor)
# added: 2026-10-12     (obrigatório)
# expires: 2026-11-11   (omitido = added + 30 dias)
1.2.3.4
evil.example.com
```

Ao expirar, o ficheiro deixa de contar e o build seguinte apaga-o.
