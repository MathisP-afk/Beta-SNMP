# 🚢 SETUP COMPLET - DOCKER WINDOWS (5 MIN)

**Copie-colle ces commandes dans PowerShell et c'est bon!**

---

## ⚠️ PRÉREQUIS ABSOLUS

1. **Docker Desktop installé**
   - Télécharge: https://www.docker.com/products/docker-desktop
   - Lance Docker Desktop
   - Attends qu'il soit completément démarré (événement en bas à droite)

2. **Python venv activé**
   ```powershell
   cd C:\snmp_project\Beta-SNMP
   .\venv\Scripts\Activate.ps1
   ```

3. **Git branch correct**
   ```powershell
   git checkout snmpv3-collector-v2
   git pull origin snmpv3-collector-v2
   ```

---

## 🚀 STEP 1: DÉMARRER DOCKER POSTGRESQL (30 SEC)

```powershell
cd C:\snmp_project\Beta-SNMP
docker-compose up -d
```

**C'est fait!** Les tables sont créées automatiquement.

Vérifie:
```powershell
docker-compose ps
```

Résultat attendu: `snmp_postgres    Up X seconds`

---

## 🚀 STEP 2: CRÉER LE FICHIER `.env` (1 MIN)

Crée le fichier `C:\snmp_project\Beta-SNMP\.env` avec ce contenu:

```bash
SNMP_HOST=192.168.1.39
SNMP_PORT=161
SNMP_USERNAME=Alleria_W
SNMP_AUTH_PASS=Vereesa_W
SNMP_PRIV_PASS=Windrunner
DB_HOST=localhost
DB_PORT=5432
DB_USER=snmp_user
DB_PASSWORD=snmp_password_secure_123
DB_NAME=snmp_db
API_HOST=0.0.0.0
API_PORT=8443
```

Sauvegarde le fichier.

---

## 🚀 STEP 3: LANCER 2 TERMINAUX

### Terminal 1: API

Ouvre **un premier PowerShell**:

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
cd "API + BDD"
python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem
```

Attends ce message:
```
INFO:     Uvicorn running on https://0.0.0.0:8443
```

Laisse ce terminal ouvert! (Ne fais pas Ctrl+C)

### Terminal 2: Collector

Ouvre **un deuxième PowerShell** (nouveau terminal):

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/snmpv3_collector_continuous.py --mode production --interval 30 --host 192.168.1.39 --username Alleria_W --auth-pass "Vereesa_W" --priv-pass "Windrunner" --verbose
```

Attends ce message:
```
[Cycle 1] Collecte de 7 OIDs...
[Cycle 1] 6/7 OIDs collectes
[Cycle 1] API Response: 200
[Cycle 1] [Statistiques] Success: 1, Errors: 0
```

Laisse ce terminal ouvert aussi!

---

## 🔍 VÉRIFIER QUE ÇA MARCHE

Ouvre **un troisième PowerShell** pour tester:

```powershell
# Test 1: Vérifier l'API
curl -k https://localhost:8443/health

# Test 2: Vérifier la BDD
psql -U snmp_user -h localhost -d snmp_db -c "SELECT COUNT(*) FROM snmp_data;"
```

Résultats attendus:
- Test 1: JSON avec `"status":"healthy"`
- Test 2: Nombre de lignes dans snmp_data (augmente toutes les 30s)

---

## 🟢 QUE SE PASSE-T-IL?

```
🚢 Terminal 1 (API)
   ↑ Écoute sur https://0.0.0.0:8443
   ↑ Attend les POST du collector
   ↑ Envoie les données à PostgreSQL

🚢 Terminal 2 (Collector)
   ↓ Scrape le switch toutes les 30s
   ↓ Collecte sysDescr, sysUpTime, sysName, etc.
   ↓ Envoie un JSON à l'API
   ↓ Répéça et recommence

🚢 Docker PostgreSQL
   ↑ Reçoit les données de l'API
   ↑ Les stocke dans snmp_data
   ↑ Elles persistent même si tu arrêtes Docker
```

---

## ⏹️ ARRÊTER

Quand tu as fini:

```powershell
# Terminal 1: Ctrl+C
# Terminal 2: Ctrl+C

# Puis arrêter Docker PostgreSQL:
docker-compose down
```

**Important:** `docker-compose down` ne supprime PAS les données! Elles seront là à la prochaine fois.

---

## 🆘 ERREUR COURANTE?

### "Port 8443 already in use"
```powershell
netstat -ano | findstr :8443
taskkill /PID <PID> /F
```

### "Connection refused" sur la BDD
```powershell
docker-compose ps  # Vérifier que snmp_postgres est "Up"
docker-compose logs postgres  # Voir les logs
```

### "Docker not found"
- Ouvre Docker Desktop
- Attends qu'il charge complètement
- Refais: `docker-compose up -d`

---

## 📚 DOCUMENTATION SI TU VEUX PLUS DE DÉTAILS

- `DOCKER_SETUP_WINDOWS.md` → Docker détaillé
- `QUICKSTART_INFRASTRUCTURE.md` → Toute l'infrastructure
- `INFRASTRUCTURE_SETUP.md` → Guide complet

---

## 🚀 VOILÀ!

C'est tout! Tu as maintenant:

- ✅ PostgreSQL qui tourne dans Docker
- ✅ API FastAPI qui scrape et sauvegarde
- ✅ Collecteur qui envoie toutes les 30s
- ✅ Données dans la BDD

**Prochaine étape: Adapter l'API pour envoyer les données à un Web UI** 🚀

