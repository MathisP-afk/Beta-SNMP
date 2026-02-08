# ⚡ WINDOWS QUICKSTART - SNMPv3 avec pysnmp 7.1.22

🌐 **Bienvenue!** Tu es sur Windows PowerShell avec **pysnmp 7.1.22**? C'est ce guide qu'il te faut! 🚀

---

## 🔍 Quelle est ta situation?

### Option 1: Tu es complètement nouveau

**→ Lance ce script PowerShell:**

```powershell
# Déjà dans C:\snmp_project\Beta-SNMP
.\test_windows.ps1
```

Ce script va:
1. ✅ Vérifier Python 3.10+
2. ✅ Installer les dépendances
3. ✅ Tester pysnmp 7.1.22
4. 📄 Afficher les prochaines étapes

**Durée: ~5 minutes**

### Option 2: Tu viens de pysnmp 5.x

L'API a **complètement changé**. Lire: **[PYSNMP_7_WINDOWS_GUIDE.md](PYSNMP_7_WINDOWS_GUIDE.md)**

### Option 3: Tu as déjà tout configuré

Passe directement à l'**[Architecture 3 Terminaux](#-architecture---3-terminaux)** ci-dessous.

---

## 🏑️ Architecture - 3 Terminaux

### Terminal 1: PostgreSQL (Docker)

```powershell
# Lancer PostgreSQL en arrière-plan
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

### Terminal 3: Collector SNMPv3

```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1

# Mode TEST (OIDs basiques, pas besoin d'un switch real)
python collector/snmpv3_collector_v7.py --mode test --verbose

# Mode PRODUCTION (si tu as un vrai switch)
python collector/snmpv3_collector_v7.py --mode production --target 192.168.1.1 --user labuser
```

### Terminal 4: Vérifier que ça marche

```powershell
# ✅ Vérifier que l'API est alive
curl -k https://localhost:8443/health

# Attendu:
# {"status":"healthy","timestamp":"...","api_version":"1.0.0"}
```

---

## 📌 Préparation Avant de Lancer

### 1. Créer le fichier .env

```powershell
Copy-Item .env.example .env
notepad .env
```

**Remplir avec tes identifiants SNMPv3:**
```bash
SNMP_USER=labuser
SNMP_AUTH_PASS=authpass          # ← Ton mot de passe
SNMP_PRIV_PASS=privpass          # ← Ton mot de passe
SNMP_TARGET_IP=192.168.1.1       # ← IP de ton switch
DB_PASSWORD=LptVmonFFVnmQUX97r597mmHqREqhBr8
```

### 2. Générer les certificats SSL

```powershell
openssl genrsa -out "API + BDD/ssl/key.pem" 2048
openssl req -new -x509 -key "API + BDD/ssl/key.pem" -out "API + BDD/ssl/fullcert.pem" -days 365 -subj "/C=FR/ST=Provence/L=Arles/O=SNMP/CN=localhost"
```

### 3. Vérifier l'installation

```powershell
python -c "import pysnmp; print(f'pysnmp {pysnmp.__version__}')"
# Attendu: pysnmp 7.1.22
```

---

## ✅ Checklist Rapide

- [ ] PowerShell lancé en **Admin**
- [ ] Python 3.10+ installé
- [ ] Git installé
- [ ] Docker installé
- [ ] `test_windows.ps1` lancé avec succès
- [ ] `.env` créé et rempli
- [ ] Certificats SSL générés
- [ ] venv créé et activé
- [ ] Dépendances installées (`pip list` ✅)
- [ ] Fichier collector/snmpv3_collector_v7.py existe

Si tout ✅: Tu es prêt pour lancer les 3 terminaux!

---

## 🚨 Erreurs Courantes

### PowerShell: "cannot be loaded because running scripts is disabled"

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "ModuleNotFoundError: No module named 'pysnmp'"

```powershell
pip install pysnmp==7.1.22 --force-reinstall --no-cache-dir
```

### "Certificate verify failed" avec HTTPS

```powershell
# Solution 1: Réinstaller les certificats
pip install pyopenssl cryptography --upgrade

# Solution 2: Utiliser -k avec curl
curl -k https://localhost:8443/health
```

### Port 8443 déjà utilisé

```powershell
netstat -ano | findstr :8443
taskkill /PID 12345 /F
```

### "Timeout" à la connexion SNMP

```powershell
# Vérifier l'accessibilité
ping 192.168.1.1

# Vérifier les identifiants SNMPv3 dans .env

# Augmenter le timeout
python collector/snmpv3_collector_v7.py --mode test --timeout 10
```

---

## 📄 Guides Complémentaires

| Guide | Contenu |
|-------|----------|
| **[README_WINDOWS_QUICKSTART.md](README_WINDOWS_QUICKSTART.md)** | Quickstart détaillé pour Windows |
| **[PYSNMP_7_WINDOWS_GUIDE.md](PYSNMP_7_WINDOWS_GUIDE.md)** | Migration pysnmp 5.x → 7.x |
| **[PySnmp Official Docs](https://pysnmp.readthedocs.io/)** | Documentation officielle |

---

## 🌟 Le Moment de Lancer!

```powershell
# Tu as suivi tout le guide?
# Ouvre 3 terminaux PowerShell en Admin et lance:

# Terminal 1: PostgreSQL
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:15

# Terminal 2: API
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
cd "API + BDD"
python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem

# Terminal 3: Collector
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/snmpv3_collector_v7.py --mode test --verbose

# Terminal 4 (test): Curl
curl -k https://localhost:8443/health
```

🎆 **Le système est oprétionnel!**

---

**Questions?** Ouvre une issue sur GitHub! 🚀
