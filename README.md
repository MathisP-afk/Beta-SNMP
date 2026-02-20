# NSMNPGN

Projet SAE 501-502 (BUT Réseaux & Télécoms, 3e année) — Outil logiciel de capture, stockage, analyse et visualisation du trafic SNMP (v2c et v3) sur un réseau local, avec détection d'anomalies de sécurité.

---

## Architecture

```
                          Réseau local
                               │
                               ▼
┌──────────────────────────────────────────────────────┐
│  RECEIVER/                                           │
│  Collecteur SNMP Unifié (Docker)                     │
│  - Capture passive Scapy (v2c + v3)                  │
│  - Polling actif SNMPv3                              │
│  - Parsing BER/ASN.1 + déchiffrement DES             │
│  - Détection de menaces (scoring par IP)             │
└──────────────┬───────────────────────┬───────────────┘
               │ POST /snmp/v2c/add    │ POST /snmp/v3/add
               ▼                       ▼
┌──────────────────────────────────────────────────────┐
│  Centrale_SQLIte/ OU Central_Postgre/                │
│  API REST FastAPI + Interface web Flet + BDD         │
│  (Docker + Traefik)                                  │
└──────────────────────────────────────────────────────┘
```

Le collecteur capture le trafic SNMP et l'envoie via API REST à la centrale. Deux variantes de centrale sont disponibles (SQLite ou PostgreSQL), chacune exposant une API FastAPI, une interface web Flet et une base de données.

---

## Composants

### `RECEIVER/` — Collecteur SNMP

Collecteur hybride SNMPv2c + SNMPv3 déployé en conteneur Docker. Capture passive via Scapy en mode promiscuous et polling actif SNMPv3 vers le switch. Intègre un parseur BER/ASN.1, le déchiffrement SNMPv3 (SHA + DES, RFC 3414) et un moteur de détection de menaces par scoring (NORMAL / SUSPECT / ELEVEE / CRITIQUE) avec tracking comportemental par IP source.

Voir [`RECEIVER/README.md`](RECEIVER/README.md) pour le guide de déploiement.

### `Centrale_SQLIte/` — Centrale SQLite

Variante légère avec base SQLite embarquée, déployable en un seul conteneur Docker. Contient l'API REST FastAPI (port 8000), l'interface web Flet (port 12000), le module d'alertes SMS Twilio et le module d'émission SNMP.

Voir [`Centrale_SQLIte/README.md`](Centrale_SQLIte/README.md) pour le guide de déploiement.

### `Central_Postgre/` — Centrale PostgreSQL

Variante avec base PostgreSQL, déployable via Docker Compose avec reverse-proxy Traefik (HTTPS automatique via Let's Encrypt). Mêmes fonctionnalités que la variante SQLite, adaptée à un déploiement en production.

Voir [`Central_Postgre/README.md`](Central_Postgre/README.md) pour le guide de déploiement.

### `tests/` — Tests unitaires

4 suites de tests exécutées automatiquement par la pipeline CI :

| Fichier | Composant testé |
|---|---|
| `test_snmp_collector_unified.py` | Parseur BER, parsing v2c/v3, dérivation clé SHA, IPTracker, file d'attente |
| `test_centrale_sqlite.py` | API REST SQLite, base de données, endpoints |
| `test_centrale_postgre.py` | API REST PostgreSQL, base de données, endpoints |
| `test_sms_alerter.py` | Module d'alertes SMS Twilio (mocks) |

---

## CI/CD

Pipeline GitHub Actions (`.github/workflows/ci.yml`) déclenchée sur push et pull request vers `main` et `preprod` :

1. **Analyse statique** : Pylint sur les 3 composants principaux
2. **Tests unitaires** : 4 suites de tests (collecteur, SQLite, PostgreSQL, SMS)

---

## Technologies

| Catégorie | Technologies |
|---|---|
| Capture réseau | Scapy, pysnmp, pycryptodomex |
| API REST | FastAPI, Uvicorn |
| Base de données | SQLite / PostgreSQL (psycopg2) |
| Interface web | Flet |
| Alertes | Twilio (SMS) |
| Analyse IA | Ollama (LLM local) |
| Conteneurisation | Docker, Docker Compose, Traefik |
| CI/CD | GitHub Actions |
| Langage | Python 3.10 |

---

## Structure du dépôt

```
Beta-SNMP/
├── .github/workflows/ci.yml       # Pipeline CI/CD GitHub Actions
├── RECEIVER/                       # Collecteur SNMP unifié (Docker)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│   ├── .env.example
│   ├── snmp_collector_unified.py
│   ├── generate_alerts.py
│   └── README.md
├── Centrale_SQLIte/                # Centrale SQLite (Docker)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── snmp_api_improved.py
│   ├── snmp_database.py
│   ├── snmp_gui_web.py
│   ├── snmp_sender.py
│   ├── sms_alerter.py
│   ├── init_db.py
│   └── README.md
├── Central_Postgre/                # Centrale PostgreSQL (Docker + Traefik)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-compose_light.yml
│   ├── requirements.txt
│   ├── snmp_api_improved_postgre.py
│   ├── snmp_database_postgre.py
│   ├── snmp_gui_web.py
│   ├── snmp_sender.py
│   ├── sms_alerter.py
│   ├── init_db.py
│   └── README.md
├── tests/                          # Tests unitaires
│   ├── test_snmp_collector_unified.py
│   ├── test_centrale_sqlite.py
│   ├── test_centrale_postgre.py
│   └── test_sms_alerter.py
└── .gitignore
```
