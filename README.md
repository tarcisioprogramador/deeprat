# Pentest Tools API

Ferramentas locais de penetration testing com interface web.

## Deploy no Railway

### Opção 1: One-Click Deploy
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/tarcisioprogarmador/deeprat)

### Opção 2: Manual
1. Acesse https://railway.app
2. Login com GitHub
3. New Project → Deploy from GitHub repo
4. Selecione: tarcisioprogarmador/deeprat
5. Aguarde deploy
6. Settings → Networking → Generate Domain

## Funcionalidades

- Análise de senhas
- Geração de wordlists
- Comandos (nmap, metasploit, hydra, sqlmap)
- Análise de vulnerabilidades
- Privilege escalation
- Força bruta
- Web vulnerability scanner
- Chat IA (DeepHat via Hugging Face)

## Rodar local

```bash
pip install -r requirements.txt
python app.py
```

Acesse: http://localhost:5000
