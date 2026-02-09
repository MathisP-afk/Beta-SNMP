# 🚀 QUICKSTART - INFRASTRUCTURE COMPLÈTE EN 10 MIN

**Guide rapide pour lancer: PostgreSQL Docker → API → Collector Continu**

---

## ☝ PRÉREQUIS VÉRIFIÉS

- ✅ Docker Desktop installé (https://www.docker.com/products/docker-desktop)
- ✅ Python 3.10+ avec venv activé dans `C:\snmp_project\Beta-SNMP`
- ✅ Switch SG250 configuré SNMPv3 (192.168.1.39)
- ✅ Git clone `snmpv3-collector-v2` branch

---

## ✏️ STEP 1: LANCER POSTGRESQL EN DOCKER (2 MIN)

```powershell
cd C:\snmp_project\Beta-SNMP

# Récupère les fichiers Docker
git pull origin snmpv3-collector-v2

# Démarre PostgreSQL en container
docker-compose up -d

# Vérifie que ça marche
docker-compose ps

# Résultat attendu:
# NAME              STATUS
# snmp_postgres    Up 2 seconds
```

✅ **PostgreSQL est maintenant running sur localhost:5432**

**Les tables sont créées automatiquement** (voir init.sql)

---

## ✏️ STEP 2: VÉRIFIER LA BDD

```powershell
# Se connecter à la BDD
psql -U snmp_user -h localhost -d snmp_db

# Une fois dedans:
SELECT * FROM collectors;
\q

# Résultat attendu:
# id |   name    | ip_address  | port | snmp_user
# 1  | SG250-Test| 192.168.1.39| 161  | Alleria_W
```

---

## ✏️ STEP 3: SETUP `.env` (2 MIN)

Crée `C:\snmp_project\Beta-SNMP\.env`:

```bash
# ===== SNMP =====
SNMP_HOST=192.168.1.39
SNMP_PORT=161
SNMP_USERNAME=Alleria_W
SNMP_AUTH_PASS=Vereesa_W
SNMP_PRIV_PASS=Windrunner

# ===== DATABASE (DOCKER) =====
DB_HOST=localhost
DB_PORT=5432
DB_USER=snmp_user
DB_PASSWORD=snmp_password_secure_123
DB_NAME=snmp_db

# ===== API =====
API_HOST=0.0.0.0
API_PORT=8443
API_SSL_KEYFILE=API + BDD/ssl/key.pem
API_SSL_CERTFILE=API + BDD/ssl/fullcert.pem

# ===== COLLECTOR =====
COLLECTOR_INTERVAL=30
COLLECTOR_MODE=production
```

---

## 🚀 STEP 4: LANCER L'INFRASTRUCTURE (3 TERMINAUX)

### Terminal 1: API REST (Port 8443)

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

cd "API + BDD"
python -m uvicorn snmp_api_improved:app `
  --host 0.0.0.0 `
  --port 8443 `
  --ssl-keyfile ssl/key.pem `
  --ssl-certfile ssl/fullcert.pem

# Attends ce message:
# INFO:     Uvicorn running on https://0.0.0.0:8443
```

### Terminal 2: Collector Continu (Scraping en boucle)

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

python collector/snmpv3_collector_continuous.py `
  --mode production `
  --interval 30 `
  --host 192.168.1.39 `
  --username Alleria_W `
  --auth-pass "Vereesa_W" `
  --priv-pass "Windrunner" `
  --verbose

# Attends ce message:
# [Cycle 1] Collecte de 7 OIDs...
# [Cycle 1] 6/7 OIDs collectes
# [Cycle 1] API Response: 200
```

### Terminal 3: Monitoring & Tests

```powershell
# ✅ Test 1: API Health
curl -k https://localhost:8443/health

# ✅ Test 2: Consulter les collecteurs
curl -k https://localhost:8443/api/collectors

# ✅ Test 3: Consulter les dernières données
curl -k https://localhost:8443/api/data/latest?collector_id=1

# ✅ Test 4: Consulter la BDD
psql -U snmp_user -h localhost -d snmp_db -c "SELECT COUNT(*) as data_count FROM snmp_data;"
```

---

## 📋 AFFICHAGE ATTENDU

### Terminal 1 (API):
```
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
INFO:     Application startup complete
INFO:     POST /api/snmp/data/ingest 200
INFO:     POST /api/snmp/data/ingest 200
```

### Terminal 2 (Collector):
```
2026-02-09 09:00:00,123 - INFO - 
======================================================================
COLLECTOR CONTINU - Mode PRODUCTION
Host: 192.168.1.39:161
API: https://localhost:8443
Intervalle: 30s
======================================================================

2026-02-09 09:00:00,124 - INFO - [Cycle 1] Collecte de 7 OIDs...
2026-02-09 09:00:00,462 - DEBUG - [sysDescr] = SG250-08 8-Port Gigabit Smart Switch
2026-02-09 09:00:01,219 - INFO - [Cycle 1] 6/7 OIDs collectes
2026-02-09 09:00:01,350 - INFO - [Cycle 1] API Response: 200
```

### Terminal 3 (Tests):
```powershell
PS> curl -k https://localhost:8443/health
{"status":"healthy","timestamp":"2026-02-09T09:00:30Z"}

PS> psql -U snmp_user -h localhost -d snmp_db -c "SELECT COUNT(*) FROM snmp_data;"
 count
-------
    15
(1 row)
```

---

## 🔧 TROUBLESHOOTING

### ❌ "docker: command not found"
Installer Docker Desktop depuis: https://www.docker.com/products/docker-desktop
Rédémarrer PowerShell après installation

### ❌ "Port 5432 already allocated"
```powershell
docker-compose down
```

### ❌ "Connection refused" sur BDD
Vérifier que le container est actif:
```powershell
docker-compose ps
```

### ❌ "SNMP timeout"
- Vérifier que le switch est accessible: `ping 192.168.1.39`
- Vérifier les credentials SNMPv3 dans `.env`

---

## ⏹️ ARRÊTER TOUT

Dans chaque terminal: **Ctrl+C**

```powershell
# Arrêter PostgreSQL (les données sont préservées)
docker-compose down
```

---

## ✅ PROCHAINES ÉTAPES

1. ✅ PostgreSQL Docker lancé et testé
2. ✅ API REST running
3. ✅ Collector continu envoyant les données
4. ⏳ Adapter `snmp_database.py` pour INSERT/UPDATE dans PostgreSQL
5. ⏳ Enrichir l'API avec plus d'endpoints
6. ⏳ Créer le Web UI (dashboards temps réel)

---

## 📚 DOCUMENTATION COMPLÉMENTAIRE

- `DOCKER_SETUP_WINDOWS.md` → Guide Docker détaillé
- `INFRASTRUCTURE_SETUP.md` → Guide installation complète
- `collector/snmpv3_collector_continuous.py` → Collecteur en boucle

**Tu as un doute? Revois le fichier complet!**

