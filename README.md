# ⚡ DÉMARRAGE RAPIDE (5 MINUTES)

Si tu es pressé, voici les commandes essentielles **copy-paste** pour Windows.

---

## 🚀 Commandes Rapides (PowerShell Admin)

```powershell
# 1️⃣ CLONER & SETUP (3 min)
cd C:\
mkdir snmp_project && cd snmp_project
git clone https://github.com/MathisP-afk/Beta-SNMP.git
cd Beta-SNMP
git checkout -b snmpv3-collector-v2

# 2️⃣ PERMISSION POWERSHELL (⚠️ OBLIGATOIRE)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Répondre "Y" pour Oui

# 3️⃣ VENV & DÉPENDANCES (2 min)
python -m venv venv
.\venv\Scripts\Activate.ps1
# Résultat: (venv) PS C:\snmp_project\Beta-SNMP>
pip install --upgrade pip
pip install -r requirements.txt

# 4️⃣ TEST SNMP (3 Terminaux)

# Terminal 1: Mock SNMP Agent (simule un switch)
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/mock_snmp_agent.py --port 1161
# Résultat: "Mock SNMP Agent SNMPv3 DÉMARRÉ"

# Terminal 2: Collector (collecte les OIDs)
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/snmpv3_collector.py --mode test --host 127.0.0.1 --port 1161 --verbose
# Résultat: OK - 4 OIDs collectés

# Terminal 3: LANCER L'API (optionnel)
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
cd "API + BDD"
python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem
```

---

## ✅ Checklist Minimaliste

| Étape | Commande | Résultat |
|-------|----------|----------|
| Python | `python --version` | `Python 3.10+` |
| Git | `git --version` | `git version 2.x+` |
| Clone | `git clone ...` | Dossier `/Beta-SNMP` |
| venv | `python -m venv venv` | Dossier `/venv` |
| Permission PS | `Set-ExecutionPolicy RemoteSigned ...` | Pas d'erreur |
| Activer | `.\venv\Scripts\Activate.ps1` | Prompt: `(venv) PS ...` |
| Dépendances | `pip install -r requirements.txt` | Pas d'erreur |
| Mock Agent | `python collector/mock_snmp_agent.py --port 1161` | "Mock Agent DÉMARRÉ" |
| Collector | `python collector/snmpv3_collector.py --mode test` | "4 OIDs collectés" |

---

## 🔗 OIDs Testés en Mode TEST

```
- sysDescr (1.3.6.1.2.1.1.1.0)
- sysUpTime (1.3.6.1.2.1.1.3.0)
- sysName (1.3.6.1.2.1.1.5.0)
- sysLocation (1.3.6.1.2.1.1.6.0)
```

**Mode PRODUCTION** ajoute:
```
- Interfaces (ifTable)
- Performance CPU/RAM
- Traps
```

---

## 🆘 Problèmes Courants

### ❌ PowerShell: "n'est pas reconnu" / Activation venv échoue

**Solution:**
```powershell
# Admin PowerShell:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Vérifier:
Get-ExecutionPolicy
# Résultat: RemoteSigned

# Puis activation:
.\venv\Scripts\Activate.ps1
```

→ **Voir TROUBLESHOOTING.md pour plus de solutions**

### ❌ SNMP Timeout: "No SNMP response received before timeout"

**Cause:** Pas d'agent SNMP sur `127.0.0.1:161`

**Solution:** Lancer le Mock Agent dans Terminal 1:
```powershell
python collector/mock_snmp_agent.py --port 1161
```

→ **Voir TROUBLESHOOTING.md pour les alternatives**

### ❌ "ModuleNotFoundError: No module named 'pysnmp'"
```powershell
pip install pysnmp==7.1.22 --force-reinstall
```

### ❌ "psycopg2 not found"
```powershell
pip install psycopg2-binary>=2.9
```

### ❌ Port 8443 déjà utilisé
```powershell
netstat -ano | findstr :8443
taskkill /PID 12345 /F
# Ou changer le port: --port 8444
```

### ❌ Erreur SSL "certificate verify failed"
Ajouter `-k` à **tous** les `curl`:
```powershell
curl -k https://localhost:8443/health
```

---

## 📍 Fichiers Clés

```
Beta-SNMP/
├── collector/                      # ← Collector SNMP
│   ├── snmpv3_collector.py        # Collecteur SNMPv3 (ASYNC pysnmp 7.1.22)
│   ├── mock_snmp_agent.py         # Mock agent pour tester
│   └── requirements_collector.txt
├── API + BDD/
│   ├── snmp_api_improved.py       # ✗ NE PAS MODIFIER
│   ├── snmp_database.py            # ← À modifier (PostgreSQL)
│   └── ssl/
│       ├── key.pem                # ← À générer
│       └── fullcert.pem           # ← À générer
├── .env.example                    # ← Copier en .env
├── .env                            # ← Créer & éditer
├── requirements.txt                # ← À mettre à jour
├── TROUBLESHOOTING.md              # ← Guide dépannage
└── venv/                           # ← python -m venv venv
```

---

## 🎯 Résumé

1. **Clone** → `git clone ... && git checkout -b snmpv3-collector-v2`
2. **Permission** → `Set-ExecutionPolicy RemoteSigned`
3. **venv** → `python -m venv venv && .\venv\Scripts\Activate.ps1`
4. **Dépendances** → `pip install -r requirements.txt`
5. **Mock Agent** (Terminal 1) → `python collector/mock_snmp_agent.py --port 1161`
6. **Collector** (Terminal 2) → `python collector/snmpv3_collector.py --mode test`
7. **Test** (Terminal 3) → `curl -k https://localhost:8443/health` (optionnel)

**Durée: ~30 minutes ⏱️**

Pour le détail complet → Voir **TUTORIEL_COMPLET_WINDOWS.md** ou **TROUBLESHOOTING.md**

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ SNMP Collector (snmpv3_collector.py)                       │
│  ├─ SNMPv3 GET requests                                    │
│  └─ Collect OIDs: sysDescr, sysUpTime, sysName, etc.      │
└─────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────┐
│ Mock SNMP Agent (mock_snmp_agent.py) - PORT 1161           │
│  ├─ Simule un device Cisco                                 │
│  └─ MIB-II: system group (1.3.6.1.2.1.1.x)                │
└─────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────┐
│ API REST (snmp_api_improved.py) - PORT 8443 (HTTPS)        │
│  ├─ POST /snmp/collect                                     │
│  └─ GET /health                                            │
└─────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────┐
│ PostgreSQL Database (snmp_database.py)                      │
│  ├─ Table: snmp_collections                                │
│  └─ Table: devices                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Prochaines Étapes

1. ✅ Installer et tester le collector
2. 🔜 Connecter à un vrai device SNMP
3. 🔜 Configurer PostgreSQL
4. 🔜 Lancer l'API REST
5. 🔜 Visualiser les données en temps réel

---

**Questions ou problèmes?** → Voir `TROUBLESHOOTING.md` 🆘
