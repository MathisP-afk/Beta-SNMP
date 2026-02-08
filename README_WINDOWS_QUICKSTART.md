# ⚡ WINDOWS QUICKSTART - pysnmp 7.1.22

**Durée: ~15 minutes** | **OS: Windows 10/11** | **Python: 3.10+** | **SNMPv3: OUI**

> 🚨 **NOTE**: Tu es passé à **pysnmp 7.1.22**. L'API a changé par rapport à 5.x. Ce guide c'est pour toi.

---

## 🚀 Lancement Rapide (Copy-Paste)

### Terminal 1: PowerShell Admin - Setup Initial

```powershell
# 1️⃣ Vérifier Python 3.10+
python --version

# 2️⃣ Aller au dossier du projet
cd C:\snmp_project\Beta-SNMP

# 3️⃣ Créer et activer le venv
python -m venv venv
.\venv\Scripts\Activate.ps1

# 4️⃣ Installer pysnmp 7.1.22
pip install --upgrade pip setuptools wheel
pip install pysnmp==7.1.22 pyopenssl cryptography
pip install -r requirements.txt

# 5️⃣ Vérifier l'installation
python -c "import pysnmp; print(f'pysnmp: {pysnmp.__version__}')"
# Attendu: pysnmp: 7.1.22
```

### Terminal 2: Test Automatique (PowerShell Admin)

```powershell
# 🧹 Script test tout inclus
cd C:\snmp_project\Beta-SNMP
.\test_windows.ps1
```

Ce script va:
- ✅ Vérifier Python, Git, Docker
- ✅ Installer les dépendances
- ✅ Tester pysnmp 7.1.22
- ✅ Afficher les prochaines étapes

### Terminal 3: Lancer le Collector (Mode TEST)

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

# Mode TEST (OIDs basiques)
python collector/snmpv3_collector_v7.py --mode test --verbose

# Ou mode PRODUCTION
python collector/snmpv3_collector_v7.py --mode production --target 192.168.1.1 --user labuser
```

**Sortie attendue:**
```
🧪 MODE TEST - Collecte OIDs basiques
📄 Collecte sysDescr (1.3.6.1.2.1.1.1.0)...
  ✅ Réussi: Cisco IOS Software Release ...
📄 Collecte sysUpTime (1.3.6.1.2.1.1.3.0)...
  ✅ Réussi: 123456789
```

---

## 📌 Configuration

### 1. Créer le fichier .env

```powershell
# Dans C:\snmp_project\Beta-SNMP
Copy-Item .env.example .env
notepad .env
```

**Contenu .env:**
```bash
# SNMPv3
SNMP_VERSION=3
SNMP_USER=labuser
SNMP_AUTH_PROTOCOL=hmac_sha
SNMP_AUTH_PASS=authpass           # ← Ton mot de passe d'auth
SNMP_PRIV_PROTOCOL=aes
SNMP_PRIV_PASS=privpass           # ← Ton mot de passe de chiffrement

# Target
SNMP_TARGET_IP=192.168.1.1        # ← IP de ton switch
SNMP_TARGET_PORT=161

# PostgreSQL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=snmpdatabase
DB_USER=SylvAdminBDD
DB_PASSWORD=LptVmonFFVnmQUX97r597mmHqREqhBr8
```

### 2. Générer les certificats SSL

```powershell
# Dans C:\snmp_project\Beta-SNMP

# Générer clé privée
openssl genrsa -out "API + BDD/ssl/key.pem" 2048

# Générer certificat
openssl req -new -x509 -key "API + BDD/ssl/key.pem" -out "API + BDD/ssl/fullcert.pem" -days 365 -subj "/C=FR/ST=Provence/L=Arles/O=SNMP/CN=localhost"

# Vérifier
ls "API + BDD/ssl/"
# Attendu: fullcert.pem, key.pem
```

---

## 🏑️ Architecture - 3 Terminaux

### Terminal 1: PostgreSQL (Docker)

```powershell
# Lancer PostgreSQL
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:15

# Attendu:
# database system is ready to accept connections
```

### Terminal 2: API FastAPI (HTTPS)

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
cd "API + BDD"
python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem

# Attendu:
# Uvicorn running on https://0.0.0.0:8443
```

### Terminal 3: Collector (Mode Test puis Prod)

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

# Mode TEST
python collector/snmpv3_collector_v7.py --mode test --verbose

# Attendre 30s...
# Mode PRODUCTION (avec ta vraie IP)
python collector/snmpv3_collector_v7.py --mode production --target 192.168.1.1 --collection standard
```

### Terminal 4: Test l'API

```powershell
# ✅ Vérifier que l'API est alive
curl -k https://localhost:8443/health

# Résultat:
# {"status":"healthy","timestamp":"2026-02-08T..."}

# 📋 Récupérer les stats des paquets
curl -k https://localhost:8443/api/packets/stats

# 📚 Récupérer les paquets reçus
curl -k https://localhost:8443/api/packets?limit=10
```

---

## ✅ Checklist de Lancement

- [ ] Python 3.10+ installé
- [ ] `python --version` ➤ Python 3.10+
- [ ] `pip show pysnmp` ➤ Version 7.1.22
- [ ] `pip show cryptography` ➤ 40.0+
- [ ] `pip show pyopenssl` ➤ 22.0+
- [ ] `.env` créé et rempli
- [ ] Certificats SSL générés (key.pem, fullcert.pem)
- [ ] PostgreSQL Docker lancé (port 5432)
- [ ] API FastAPI lancée (port 8443)
- [ ] Collector mode TEST lancé avec succès
- [ ] `curl -k https://localhost:8443/health` ➤ 200 OK
- [ ] Fichier `collector_results_*.json` généré

---

## 🚨 Erreurs Courantes

### ❌ "ModuleNotFoundError: No module named 'pysnmp'"

```powershell
pip install pysnmp==7.1.22 --force-reinstall --no-cache-dir
```

### ❌ "Certificate verify failed" (HTTPS)

**Solution 1: Réinstaller les certificats**
```powershell
pip install pyopenssl cryptography --upgrade
```

**Solution 2: Utiliser -k avec curl**
```powershell
curl -k https://localhost:8443/health
```

### ❌ "Port 8443 déjà utilisé"

```powershell
# Trouver le PID
netstat -ano | findstr :8443

# Tuer le processus
taskkill /PID 12345 /F

# Ou utiliser un autre port
python -m uvicorn snmp_api_improved:app --port 8444
```

### ❌ "PowerShell: cannot be loaded"

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### ❌ "Timeout" à la connexion SNMP

```powershell
# Vérifier que le switch est accessible
ping 192.168.1.1

# Vérifier les identifiants SNMPv3
# Vérifier le firewall Windows

# Augmenter le timeout
python collector/snmpv3_collector_v7.py --mode test --timeout 10
```

---

## 📄 Fichiers Créés

```
Beta-SNMP/
├─ PYSNMP_7_WINDOWS_GUIDE.md       ← Documentation détaillée
├─ README_WINDOWS_QUICKSTART.md    ← CE FICHIER
├─ test_windows.ps1               ← Script test PowerShell
├─ collector/
│  └─ snmpv3_collector_v7.py         ← Collector pour pysnmp 7.x
├─ requirements.txt                ← Dépendances (mis à jour)
├─ .env                            ← À créer
├─ API + BDD/
│  └─ ssl/
│      ├─ key.pem                 ← À générer
│      └─ fullcert.pem           ← À générer
├─ venv/                           ← À créer
└─ logs/                           ← Fichiers de log
```

---

## 🌟 Prochaines Étapes

1. **Tester le mode TEST**
   ```powershell
   python collector/snmpv3_collector_v7.py --mode test --verbose
   ```

2. **Tester le mode PRODUCTION** (si tu as un switch)
   ```powershell
   python collector/snmpv3_collector_v7.py --mode production --target 192.168.1.1 --user labuser
   ```

3. **Consulter le guide détaillé**
   ```
   PYSNMP_7_WINDOWS_GUIDE.md
   ```

4. **Déboguer si besoin**
   ```powershell
   python collector/snmpv3_collector_v7.py --mode test --log-level DEBUG --verbose
   ```

---

## 📚 Documentation Complète

- **[PYSNMP_7_WINDOWS_GUIDE.md](PYSNMP_7_WINDOWS_GUIDE.md)** - Guide complet pysnmp 7.x
- **[PySnmp Official Docs](https://pysnmp.readthedocs.io/)** - Documentation officielle
- **[PySnmp 7.x Migration](https://github.com/lextudio/pysnmp/wiki/Migration)** - Guide de migration

---

**🚀 Prêt pour décoller! Lance le test_windows.ps1 et tu seras oprérationnel en 15 minutes.**
