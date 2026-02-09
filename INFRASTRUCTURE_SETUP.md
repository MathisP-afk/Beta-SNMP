# 🚀 INFRASTRUCTURE COMPLÈTE - SNMP v3 → API → PostgreSQL → Web

**Guide détaillé pour lancer toute l'infrastructure en local sur Windows.**

---

## 📋 Prérequis

- ✅ Python 3.10+
- ✅ PostgreSQL 14+ (voir section Installation PostgreSQL)
- ✅ Git
- ✅ PowerShell (Admin)
- ✅ SNMPv3 configuré sur le switch (192.168.1.39)

---

## 1️⃣ INSTALLATION & CONFIGURATION POSTGRESQL

### Option A: PostgreSQL Natif (Recommandé pour dev local)

#### Installer PostgreSQL

1. Télécharge depuis [postgresql.org](https://www.postgresql.org/download/windows/)
2. Lance l'installateur
3. **Important lors de l'installation:**
   - Port: `5432` (défaut)
   - Password du user `postgres`: **à retenir!**
   - Cocher "Add PostgreSQL to PATH"

#### Vérifier l'installation

```powershell
# Vérifier que psql est accessible
psql --version

# Se connecter au serveur
psql -U postgres -h localhost
# Vous demandera le password
```

### Option B: Docker (si Docker Desktop installé)

```powershell
# Lancer PostgreSQL en container
docker run --rm -d `
  --name postgres_snmp `
  -p 5432:5432 `
  -e POSTGRES_PASSWORD=postgres_admin `
  postgres:15

# Vérifier qu'il s'écoute
docker ps | grep postgres_snmp
```

---

## 2️⃣ CRÉER LA BASE DE DONNÉES SNMP

Ouvre une session PostgreSQL et exécute:

```powershell
# Lancer psql
psql -U postgres -h localhost
```

Puis dans psql:

```sql
-- Créer la base de données
CREATE DATABASE snmp_db
  WITH
    ENCODING = 'UTF8'
    TEMPLATE = template0
    OWNER = postgres;

-- Se connecter à la base
\c snmp_db

-- Créer l'utilisateur SNMP
CREATE USER snmp_user WITH PASSWORD 'snmp_password_secure_123';

-- Donner les permissions
GRANT ALL PRIVILEGES ON DATABASE snmp_db TO snmp_user;
ALTER ROLE snmp_user CREATEDB;

-- Vérifier
\du
\l

-- Quitter
\q
```

Résultat attendu:
```
                                   List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-----------+----------+----------+-------------+-------------+-----------------------
 snmp_db   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/postgres         +
           |          |          |             |             | postgres=CTc/postgres+
           |          |          |             |             | snmp_user=CTc/postgres
```

---

## 3️⃣ CRÉER LES TABLES SNMP

Depuis n'importe quel terminal PowerShell:

```powershell
# Se connecter à la base snmp_db avec snmp_user
psql -U snmp_user -h localhost -d snmp_db
```

Puis colle ce script SQL:

```sql
-- TABLE: Collectors (sources SNMP)
CREATE TABLE collectors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    port INT DEFAULT 161,
    snmp_user VARCHAR(255) NOT NULL,
    snmp_auth_proto VARCHAR(50) DEFAULT 'SHA',
    snmp_priv_proto VARCHAR(50) DEFAULT 'DES',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, port)
);

-- TABLE: SNMP Data Points (mesures brutes)
CREATE TABLE snmp_data (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    oid VARCHAR(255) NOT NULL,
    oid_name VARCHAR(255),
    value TEXT,
    value_type VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_collector_timestamp (collector_id, timestamp),
    INDEX idx_oid_timestamp (oid, timestamp)
);

-- TABLE: System Info (dernière valeur par OID par device)
CREATE TABLE system_info (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL UNIQUE REFERENCES collectors(id) ON DELETE CASCADE,
    sys_descr TEXT,
    sys_uptime BIGINT,
    sys_name VARCHAR(255),
    sys_location VARCHAR(255),
    sys_contact VARCHAR(255),
    if_number INT,
    last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- TABLE: Interface Data (données d'interface, collecte future)
CREATE TABLE interface_data (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    if_index INT NOT NULL,
    if_name VARCHAR(255),
    if_type INT,
    if_mtu INT,
    if_speed BIGINT,
    if_admin_status INT,
    if_oper_status INT,
    if_in_octets BIGINT,
    if_out_octets BIGINT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_collector_if (collector_id, if_index)
);

-- TABLE: Alerts (alertes et anomalies)
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    alert_type VARCHAR(50),
    message TEXT,
    severity VARCHAR(50),
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

-- Insertion du collecteur de test (SG250)
INSERT INTO collectors (name, ip_address, port, snmp_user, snmp_auth_proto, snmp_priv_proto)
VALUES ('SG250-Test', '192.168.1.39', 161, 'Alleria_W', 'SHA', 'DES');

-- Vérifier
SELECT * FROM collectors;

-- Quitter
\q
```

✅ **Vérification:**

```powershell
psql -U snmp_user -h localhost -d snmp_db -c "SELECT * FROM collectors;"
```

Résultat attendu:
```
 id |    name    | ip_address  | port | snmp_user | snmp_auth_proto | snmp_priv_proto | enabled |         created_at          |         updated_at
----+------------+-------------+------+-----------+-----------------+-----------------+---------+-----------------------------+-----------------------------
  1 | SG250-Test | 192.168.1.39 |  161 | Alleria_W | SHA             | DES             | t       | 2026-02-09 08:58:00.123456  | 2026-02-09 08:58:00.123456
```

---

## 4️⃣ CONFIGURER LE FICHIER `.env`

Crée ou modifie `C:\snmp_project\Beta-SNMP\.env`:

```bash
# ===== SNMP SETTINGS =====
SNMP_HOST=192.168.1.39
SNMP_PORT=161
SNMP_USERNAME=Alleria_W
SNMP_AUTH_PASS=Vereesa_W
SNMP_PRIV_PASS=Windrunner
SNMP_MODE=production
SNMP_TIMEOUT=5

# ===== POSTGRESQL =====
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
COLLECTOR_RETRIES=3
COLLECTOR_TIMEOUT=10
COLLECTOR_MODE=production

# ===== WEB UI =====
WEB_HOST=0.0.0.0
WEB_PORT=3000
```

---

## 5️⃣ LANCER L'INFRASTRUCTURE (4 TERMINAUX)

### Terminal 1: PostgreSQL

```powershell
# Si PostgreSQL nativement installé, il fonctionne en service
# Vérifier que c'est démarré:
Get-Service postgresql-x64-*

# Ou avec Docker:
docker start postgres_snmp
docker logs -f postgres_snmp
```

### Terminal 2: API REST

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

cd "API + BDD"
python -m uvicorn snmp_api_improved:app `
  --host 0.0.0.0 `
  --port 8443 `
  --ssl-keyfile ssl/key.pem `
  --ssl-certfile ssl/fullcert.pem `
  --log-level info

# Résultat:
# INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
```

### Terminal 3: Collector (Scraping Continu)

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

# Mode production (scrape continu toutes les 30 secondes)
python collector/snmpv3_collector_continuous.py `
  --mode production `
  --interval 30 `
  --host 192.168.1.39 `
  --username Alleria_W `
  --auth-pass "Vereesa_W" `
  --priv-pass "Windrunner" `
  --verbose

# Résultat: 
# [*] Lancement du scraping continu...
# [OK] Cycle 1: 3 OIDs collectés, envoyés à l'API
# [OK] Cycle 2: 3 OIDs collectés, envoyés à l'API
# ...
```

### Terminal 4: Web UI

```powershell
cd C:\snmp_project\Beta-SNMP
cd "Web UI"

# Si tu es en Node.js/React:
npm install
npm start

# Ou si c'est un autre framework, adapter la commande

# Résultat:
# Server running on http://localhost:3000
```

---

## 6️⃣ TESTER LES CONNEXIONS

### Test 1: Base de données

```powershell
psql -U snmp_user -h localhost -d snmp_db -c "SELECT COUNT(*) FROM snmp_data;"
# Résultat: count
#           -----
#            0
# (après les premières collectes, ce nombre augmente)
```

### Test 2: API Health Check

```powershell
curl -k https://localhost:8443/health

# Résultat:
# {"status":"healthy","timestamp":"2026-02-09T08:00:00Z",...}
```

### Test 3: API - Récupérer les collecteurs

```powershell
curl -k https://localhost:8443/api/collectors

# Résultat:
# {
#   "collectors": [
#     {
#       "id": 1,
#       "name": "SG250-Test",
#       "ip_address": "192.168.1.39",
#       ...
#     }
#   ]
# }
```

### Test 4: API - Récupérer les dernières données

```powershell
curl -k https://localhost:8443/api/data/latest?collector_id=1

# Résultat:
# {
#   "data": [
#     {
#       "oid": "1.3.6.1.2.1.1.1.0",
#       "oid_name": "sysDescr",
#       "value": "SG250-08 8-Port Gigabit Smart Switch",
#       "timestamp": "2026-02-09T08:00:00Z"
#     },
#     ...
#   ]
# }
```

### Test 5: Web UI

Ouvre un navigateur:
```
http://localhost:3000
```

Tu devrais voir:
- Liste des collecteurs
- Graphiques en temps réel
- Tableaux de bord

---

## 7️⃣ ARRÊTER L'INFRASTRUCTURE

```powershell
# Terminal 1 (PostgreSQL): Ctrl+C ou laisser fonctionner en service

# Terminal 2 (API): Ctrl+C

# Terminal 3 (Collector): Ctrl+C

# Terminal 4 (Web): Ctrl+C
```

---

## 🆘 DÉPANNAGE

### ❌ "Could not connect to database"
- Vérifier que PostgreSQL est démarré: `psql -U postgres -h localhost`
- Vérifier les credentials dans `.env`
- Vérifier que la base `snmp_db` existe

### ❌ "SNMP timeout"
- Vérifier que le switch est accessible: `ping 192.168.1.39`
- Vérifier que SNMP est activé sur le switch
- Vérifier les credentials SNMPv3 (user, auth pass, priv pass)

### ❌ "Port 8443 already in use"
```powershell
netstat -ano | findstr :8443
taskkill /PID <PID> /F
```

### ❌ "SSL certificate issues"
Ajouter `-k` à tous les `curl`:
```powershell
curl -k https://localhost:8443/health
```

---

## 📊 ARCHITECTURE FINALE

```
Switch (192.168.1.39:161)
    ↓ SNMPv3
Collector (Python)
    ↓ HTTP POST JSON
API (FastAPI:8443)
    ↓ SQL
PostgreSQL (5432)
    ↓ REST API
Web UI (React:3000)
```

---

## 📝 FICHIERS DE RÉFÉRENCE

- `.env` → Configuration globale
- `collector/snmpv3_collector.py` → Collector unique
- `collector/snmpv3_collector_continuous.py` → Collector continu (à créer)
- `API + BDD/snmp_api_improved.py` → API REST
- `API + BDD/snmp_database.py` → Modèle BDD
- `Web UI/*` → Interface graphique

---

## ✅ PROCHAINES ÉTAPES

1. ✅ Configurer PostgreSQL et importer les tables
2. ⏳ Créer `snmpv3_collector_continuous.py` (voir fichier suivant)
3. ⏳ Modifier `snmp_database.py` pour faire les INSERT/UPDATE
4. ⏳ Adapter l'API pour exposer les endpoints
5. ⏳ Créer le Web UI (dashboards)

**Durée totale setup: ~45 minutes** ⏱️

