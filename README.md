# 🚀 SNMP Collector v2 - Docker Edition

**Infrastructure SNMP complète avec SNMPv3, PostgreSQL + API REST**

---

## ⚡ DÉMARRER EN 5 MIN (Windows + Docker)

**Lire ce fichier:** [`SETUP_DOCKER_WINDOWS_SIMPLE.md`](SETUP_DOCKER_WINDOWS_SIMPLE.md)

C'est 3 étapes simples:
1. Lancer Docker PostgreSQL
2. Créer le fichier `.env`
3. Lancer 2 terminaux (API + Collector)

---

## 📚 DOCUMENTATION

### Pour Windows avec Docker

| Document | Objectif |
|----------|----------|
| **[`SETUP_DOCKER_WINDOWS_SIMPLE.md`](SETUP_DOCKER_WINDOWS_SIMPLE.md)** | ⭐ **COMMENCE ICI** - Setup complet en 5 min (copy-paste) |
| [`DOCKER_SETUP_WINDOWS.md`](DOCKER_SETUP_WINDOWS.md) | Docker détaillé + troubleshooting |
| [`QUICKSTART_INFRASTRUCTURE.md`](QUICKSTART_INFRASTRUCTURE.md) | Vue d'ensemble de l'infrastructure |

---

## 🏗️ ARCHITECTURE

```
┌─────────────────────────────────────────────────────┐
│                   Windows Machine                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │   API REST  │  │  Collector  │  │  Docker   │ │
│  │  (Port      │  │   SNMPv3    │  │ PostgreSQL│ │
│  │   8443)     │  │  (scrape)   │  │ (Port 5432)│ │
│  └─────────────┘  └─────────────┘  └───────────┘ │
│       │                  │                │       │
│       └──────────────────┴────────────────┘       │
│                      │                            │
│              🔗 Données SNMP                      │
│                                                   │
└─────────────────────────────────────────────────────┘
            │
            ↓
      ┌─────────────┐
      │  Réseau     │
      │  SNMP       │
      └─────────────┘
            │
            ↓
      ┌─────────────┐
      │  Switch     │
      │  SG250      │
      └─────────────┘
```

---

## ✅ CHECKLIST D'INSTALLATION

- [ ] Docker Desktop installé et lancé
- [ ] Python 3.10+ avec venv
- [ ] Git branch `snmpv3-collector-v2`
- [ ] `docker-compose up -d` → PostgreSQL running
- [ ] Fichier `.env` créé
- [ ] API lancée sur `https://0.0.0.0:8443`
- [ ] Collector lancé et envoyant des données
- [ ] Test: `curl -k https://localhost:8443/health`

---

## 🔗 COMPOSANTS

### PostgreSQL (Docker Container)

```powershell
docker-compose up -d
```

- Image: `postgres:15-alpine`
- Container: `snmp_postgres`
- Port: `5432`
- User: `snmp_user` / Password: `snmp_password_secure_123`
- Database: `snmp_db`
- **Tables créées automatiquement** par `init.sql`

### API REST (FastAPI)

Endpoints disponibles:

```
GET  /health                          → État de l'API
GET  /api/collectors                  → Liste des devices
GET  /api/data/latest                 → Dernières données
POST /api/snmp/data/ingest            → Recevoir les données du collector
```

### Collector (SNMPv3)

Scrape le switch toutes les **30 secondes** et envoie les données à l'API.

OIDs collectés (mode `production`):
- `sysDescr` - Description du device
- `sysUpTime` - Uptime
- `sysName` - Nom du device
- `sysLocation` - Localisation
- + Interfaces, CPU, RAM, etc.

---

## 🆘 DÉPANNAGE RAPIDE

### Docker ne démarre pas

```powershell
# 1. Lance Docker Desktop
# 2. Attends 30 secondes
# 3. Réessaye:
docker-compose up -d
```

### Port 8443 déjà utilisé

```powershell
netstat -ano | findstr :8443
taskkill /PID <PID> /F
```

### Connection refused sur la BDD

```powershell
docker-compose ps          # Vérifie que snmp_postgres est "Up"
docker-compose logs postgres  # Voir les logs
```

**Plus de détails → Voir [`DOCKER_SETUP_WINDOWS.md`](DOCKER_SETUP_WINDOWS.md)**

---

## 🎯 PROCHAINES ÉTAPES

1. ✅ Infrastructure lancée
2. ✅ Données collectées dans PostgreSQL
3. ⏳ Créer un Web UI (dashboards temps réel)
4. ⏳ Alertes et notifications
5. ⏳ Export des données (CSV, JSON, etc.)

---

## 📁 STRUCTURE DU PROJET

```
Beta-SNMP/
├── API + BDD/
│   ├── snmp_api_improved.py      ← API FastAPI
│   ├── snmp_database.py          ← Gestion BDD
│   └── ssl/
│       ├── key.pem               ← Certificat SSL
│       └── fullcert.pem
├── collector/
│   └── snmpv3_collector_continuous.py  ← Collecteur en boucle
├── docker-compose.yml            ← Configuration Docker
├── init.sql                      ← Schéma BDD (auto-exécuté)
├── requirements.txt              ← Dépendances Python
├── .env                          ← Variables d'environnement
└── README.md                     ← Ce fichier
```

---

## 🚀 VERSION & CHANGELOG

**v2.0** (Février 2026)
- ✅ SNMPv3 collector fonctionnel
- ✅ Docker PostgreSQL
- ✅ API REST FastAPI
- ✅ Collector continu (scrape toutes les 30s)
- ✅ Documentation simplifiée

---

## 📞 BESOIN D'AIDE?

1. Lire [`SETUP_DOCKER_WINDOWS_SIMPLE.md`](SETUP_DOCKER_WINDOWS_SIMPLE.md) (démarrage)
2. Lire [`DOCKER_SETUP_WINDOWS.md`](DOCKER_SETUP_WINDOWS.md) (Docker détaillé)
3. Lire [`QUICKSTART_INFRASTRUCTURE.md`](QUICKSTART_INFRASTRUCTURE.md) (vue complète)

---

**Made with ❤️ for SNMP monitoring on Windows**

