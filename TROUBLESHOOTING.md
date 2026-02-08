# 🔧 TROUBLESHOOTING - Problèmes Courants

## ❌ PowerShell: "n'est pas reconnu" / Activation venv échoue

**Problème:**
```powershell
.\venv\Scripts\Activate.ps1 : Le terme «.\venv\Scripts\Activate.ps1» n'est pas reconnu
```

**Solution 1: Changer la Execution Policy (RECOMMANDÉ)**
```powershell
# En tant qu'Admin PowerShell:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Vérifier:
Get-ExecutionPolicy
# Résultat: RemoteSigned

# Puis activation:
.\venv\Scripts\Activate.ps1
# Prompt: (venv) PS C:\snmp_project\Beta-SNMP>
```

**Solution 2: Utiliser CMD.exe à la place**
```cmd
REM Depuis CMD (pas PowerShell):
cd C:\snmp_project\Beta-SNMP
venv\Scripts\activate.bat
REM Prompt: (venv) C:\snmp_project\Beta-SNMP>
```

**Solution 3: Utiliser Python directement**
```powershell
# Sans activer venv, juste lancer avec python complet:
C:\snmp_project\Beta-SNMP\venv\Scripts\python.exe collector/snmpv3_collector.py --mode test
```

---

## ❌ "ModuleNotFoundError: No module named 'pysnmp'" (même après pip install)

**Problème:**
```
pip install -r requirements.txt
# Installation réussie, mais:
python collector/mock_snmp_agent.py
ModuleNotFoundError: No module named 'pysnmp'
```

**Cause:** pip installe dans le répertoire **utilisateur global** (`AppData\Local\Packages\Python...`) au lieu du venv

**Message tipique:**
```
Defaulting to user installation because normal site-packages is not writeable
```

**Solution (OBLIGATOIRE):**
```powershell
# 1️⃣ S'assurer que le venv est bien activé
.\venv\Scripts\Activate.ps1
# Prompt DOIT commencer par (venv)

# 2️⃣ DÉSACTIVER le user site-packages
set PYTHONUSERBASE=

# 3️⃣ Réinstaller DANS le venv (pas globalement)
pip install --no-user -r requirements.txt

# OU forcer avec --target:
pip install --no-user --force-reinstall pysnmp==7.1.22

# 4️⃣ Vérifier que c'est installé dans le venv
python -c "import sys; print(sys.path)"
# Doit afficher: C:\snmp_project\Beta-SNMP\venv\Lib\site-packages
```

**Si ça ne marche pas, réinitialiser le venv:**
```powershell
# Supprimer et recréer le venv
Rm -Recurse -Force venv
python -m venv venv
.\venv\Scripts\Activate.ps1

# Installation propre
set PYTHONUSERBASE=
pip install --no-user --upgrade pip
pip install --no-user -r requirements.txt

# Vérifier
python -c "import pysnmp; print(pysnmp.__version__)"
# Résultat: 7.1.22
```

---

## ❌ SNMP Timeout: "No SNMP response received before timeout"

**Problème:**
```
2026-02-08 17:30:38,270 - WARNING - SNMP Error: No SNMP response received before timeout
ERREUR: Impossible de recuperer sysDescr
```

**Cause:** Il n'y a **PAS d'agent SNMP** qui écoute sur `127.0.0.1:161` ou `127.0.0.1:1161`

**Solution 1: Lancer un Mock SNMP Agent (RECOMMANDÉ pour TEST)**

Crée `collector/mock_snmp_agent.py` (déjà créé dans le repo):

**Puis lancer en 2 terminaux:**

**Terminal 1: Mock Agent**
```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/mock_snmp_agent.py --port 1161
# Résultat: "🎭 Mock SNMP Agent - SNMPv3 Démarré"
```

**Terminal 2: Collector**
```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/snmpv3_collector.py --mode test --host 127.0.0.1 --port 1161 --verbose
# Résultat: OK - OIDs collectés ✅
```

---

**Solution 2: Utiliser un Device SNMP réel**

Si tu as un switch/routeur SNMP réel:

```powershell
python collector/snmpv3_collector.py --mode production \
  --host 192.168.1.1 \
  --port 161 \
  --username admin \
  --auth-pass monAuthPass \
  --priv-pass monPrivPass \
  --verbose
```

---

## ✅ Checklist Fixes

- [ ] `Get-ExecutionPolicy` retourne `RemoteSigned`
- [ ] Prompt commence par `(venv)`
- [ ] `python -c "import pysnmp"` fonctionne (pas d'erreur)
- [ ] Mock agent tourne sur Terminal 1
- [ ] Collector retourne des OIDs sur Terminal 2
- [ ] Pas de timeouts

---

## 🔗 Commandes Rapides de Debug

```powershell
# Vérifier que pysnmp est installé dans le venv
python -c "import pysnmp; print(pysnmp.__file__)"
# Doit afficher: C:\snmp_project\Beta-SNMP\venv\Lib\site-packages\...

# Lister tous les packages du venv
pip list

# Vérifier le chemin Python
python -c "import sys; print('\n'.join(sys.path))"

# Tester l'import async
python -c "from pysnmp.hlapi.v3arch.asyncio import get_cmd; print('OK')"
```

---

## 📚 Ressources

- [pysnmp 7.1.22 Documentation](https://docs.lextudio.com/pysnmp/v7.1/)
- [Python venv Documentation](https://docs.python.org/3/library/venv.html)
- [pip Documentation](https://pip.pypa.io/)
