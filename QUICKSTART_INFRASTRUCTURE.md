# 🚀 QUICKSTART - INFRASTRUCTURE COMPLÈTE EN 10 MIN

**Guide rapide pour lancer: PostgreSQL → API → Collector Continu → Web UI**

---

## ✋ PRÉREQUIS VERÍFIÉS

- ✅ PostgreSQL 14+ installé et démarré
- ✅ Python 3.10+ avec venv activé dans `C:\snmp_project\Beta-SNMP`
- ✅ Switch SG250 configuré SNMPv3 (192.168.1.39)
- ✅ Git clone `snmpv3-collector-v2` branch

---

## ✍️ STEP 1: CONFIGURATION POSTGRESQL (5 MIN)

### Vérifier PostgreSQL

```powershell
# Tester la connexion
psql -U postgres -h localhost

# Une fois dans psql:
\q
```

### Créer la base et l'utilisateur

Lance dans **Git Bash ou WSL** (ou une session psql):

```bash
# Se connecter en tant que postgres
psql -U postgres -h localhost << 'EOF'

CREATE DATABASE snmp_db WITH ENCODING = 'UTF8' TEMPLATE = template0;
CREATE USER snmp_user WITH PASSWORD 'snmp_password_secure_123';
GRANT ALL PRIVILEGES ON DATABASE snmp_db TO snmp_user;
ALTER ROLE snmp_user CREATEDB;

\q
EOF
```

**Ou manuellement** (ouvre psql et colle ligne par ligne):

```powershell
psql -U postgres -h localhost
```

Dans psql:
```sql
CREATE DATABASE snmp_db WITH ENCODING = 'UTF8' TEMPLATE = template0;
CREATE USER snmp_user WITH PASSWORD 'snmp_password_secure_123';
GRANT ALL PRIVILEGES ON DATABASE snmp_db TO snmp_user;
ALTER ROLE snmp_user CREATEDB;
\q
```

### Créer les tables

```powershell
psql -U snmp_user -h localhost -d snmp_db << 'EOF'

CREATE TABLE collectors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    port INT DEFAULT 161,
    snmp_user VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE snmp_data (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    oid VARCHAR(255) NOT NULL,
    oid_name VARCHAR(255),
    value TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO collectors (name, ip_address, port, snmp_user)
VALUES ('SG250-Test', '192.168.1.39', 161, 'Alleria_W');

\q
EOF
```

✅ **Verification:**

```powershell
psql -U snmp_user -h localhost -d snmp_db -c "SELECT * FROM collectors;"

# Résultat:
# id |    name    | ip_address  | port | snmp_user | enabled |       created_at
# 1  | SG250-Test | 192.168.1.39 | 161  | Alleria_W | t       | 2026-02-09 ...
```

---

## ✍️ STEP 2: SETUP `.env` (2 MIN)

Crée `C:\snmp_project\Beta-SNMP\.env`:

```bash
# ===== SNMP =====
SNMP_HOST=192.168.1.39
SNMP_PORT=161
SNMP_USERNAME=Alleria_W
SNMP_AUTH_PASS=Vereesa_W
SNMP_PRIV_PASS=Windrunner

# ===== DATABASE =====
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

## 🚀 STEP 3: LANCER L'INFRASTRUCTURE (3 TERMINAUX)

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

Ouvre un troisième PowerShell et fais les tests:

```powershell
# ✍ Test 1: API Health
curl -k https://localhost:8443/health

# ✍ Test 2: Consulter les collecteurs
curl -k https://localhost:8443/api/collectors

# ✍ Test 3: Consulter les dernières données
curl -k https://localhost:8443/api/data/latest?collector_id=1

# ✍ Test 4: Consulter la BDD
psql -U snmp_user -h localhost -d snmp_db -c "SELECT COUNT(*) as data_count FROM snmp_data;"
```

---

## 📄 ARCHITECTURE LANCÉE

```
🔁 Terminal 1 (API)
   Port 8443 | FastAPI running
   Status: READY

🔁 Terminal 2 (Collector)
   Switch 192.168.1.39:161
     ↓ SNMPv3 GET every 30s
   API 127.0.0.1:8443
     ↓ JSON POST
   PostgreSQL 127.0.0.1:5432
   
🔁 Terminal 3 (Tests)
   curl -k https://localhost:8443/...
   psql ... snmp_db
```

---

## 🟢 AFFICHAGE ATTENDU

### Terminal 1 (API):
```
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
INFO:     Application startup complete
INFO:     POST /api/snmp/data/ingest 200
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
2026-02-09 09:00:00,583 - DEBUG - [sysUpTime] = 7545400
2026-02-09 09:00:01,219 - INFO - [Cycle 1] 6/7 OIDs collectes
2026-02-09 09:00:01,350 - INFO - [Cycle 1] API Response: 200
2026-02-09 09:00:01,351 - INFO - [Statistiques] Success: 1, Errors: 0
2026-02-09 09:00:01,352 - INFO - Attente 30s avant prochain cycle...
```

### Terminal 3 (Tests):
```powershell
PS> curl -k https://localhost:8443/health
{"status":"healthy","timestamp":"2026-02-09T09:00:30Z",...}

PS> curl -k https://localhost:8443/api/data/latest?collector_id=1
{
  "data": [
    {
      "oid": "1.3.6.1.2.1.1.1.0",
      "oid_name": "sysDescr",
      "value": "SG250-08 8-Port Gigabit Smart Switch",
      "timestamp": "2026-02-09T09:00:01Z"
    },
    ...
  ]
}

PS> psql -U snmp_user -h localhost -d snmp_db -c "SELECT COUNT(*) FROM snmp_data;"
 count
-------
    15
(1 row)
```

---

## 🆘 TROUBLESHOOTING

### ❌ "Connection refused" sur Terminal 1
- Vérifier que les certificats SSL existent: `ls "API + BDD/ssl/"`
- Recréer si besoin:
  ```powershell
  cd "API + BDD/ssl"
  openssl genrsa -out key.pem 2048
  openssl req -new -x509 -key key.pem -out fullcert.pem -days 365 -subj "/C=FR/ST=Provence/L=Arles/O=SNMP/CN=localhost"
  ```

### ❌ "SNMP timeout" sur Terminal 2
- Vérifier que le switch est accessible:
  ```powershell
  ping 192.168.1.39
  ```
- Vérifier les credentials SNMPv3 dans `.env`

### ❌ "Database connection refused"
- Vérifier que PostgreSQL est démarré:
  ```powershell
  psql -U postgres -h localhost
  ```
- Vérifier le `.env` (credentials DB)

### ❌ "Port 8443 already in use"
```powershell
netstat -ano | findstr :8443
taskkill /PID <PID> /F
```

---

## ⏹️ ARRÊTER TOUT

Dans chaque terminal: **Ctrl+C**

```powershell
# PostgreSQL sera toujours actif (service Windows)
# Pour l'arrêter:
Get-Service postgresql-x64-* | Stop-Service

# Ou pour Docker:
docker stop postgres_snmp
```

---

## ✅ PROCHAINES ÉTAPES

1. ✅ Infrastructure lancée et testée
2. ⏳ Adapter `snmp_database.py` pour les INSERT/UPDATE dans PostgreSQL
3. ⏳ Enrichir l'API avec plus d'endpoints
4. ⏳ Créer le Web UI (dashboards temps réel)
5. ⏳ Ajouter les alerts/notifications

---

## 📈 DOCUMENTATION COMPLÈTE

Pour plus de détails → voir `INFRASTRUCTURE_SETUP.md`

**Vous avez un doute? Revoyez le fichier complet!**

