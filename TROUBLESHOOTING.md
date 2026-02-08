# 🔧 TROUBLESHOOTING - Problèmes Courants

## ⚠️ PROBLÈME CRITIQUE: Microsoft Store Python

Si tu as installé Python depuis **Microsoft Store**, tu vas rencontrer des problèmes de permissions.

**Symptôme:**
```
ERROR: Could not install packages due to an OSError: [WinError 5] Accès refusé
C:\Program Files\WindowsApps\...
```

**Solution:**

### **Option 1: Installer Python depuis python.org (RECOMMANDÉ)**

1. Désinstalle Python Microsoft Store:
   - Windows Settings → Apps → Installed apps
   - Cherche "Python 3.13"
   - Click "Uninstall"

2. Télécharge Python officiel:
   - Va sur [python.org](https://www.python.org/downloads/)
   - Télécharge **Python 3.13** (ou 3.12, 3.11)
   - **IMPORTANT**: Coche "Add Python to PATH" lors de l'installation

3. Vérifie:
   ```powershell
   python --version
   # Doit afficher: Python 3.13.x (pas microsoft store)
   
   python -c "import sys; print(sys.prefix)"
   # Doit afficher: C:\Users\Mathis\AppData\Local\Programs\Python\Python313
   # (pas C:\Program Files\WindowsApps\...)
   ```

4. Réinitialise le venv:
   ```powershell
   cd C:\snmp_project\Beta-SNMP
   
   # Supprimer l'ancien venv
   Remove-Item -Recurse -Force venv
   
   # Créer un nouveau venv
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   
   # Installer les dépendances
   pip install --upgrade pip
   pip install -r requirements.txt
   
   # Vérifier
   python -c "import pysnmp; print(pysnmp.__version__)"
   # Doit afficher: 7.1.22
   ```

---

### **Option 2: Utiliser WSL2 (Windows Subsystem for Linux)**

Si tu préfères rester sur Microsoft Store Python:

```powershell
# Installer WSL2
wsl --install

# Puis dans WSL:
wsl

# Installer Python
sudo apt update
sudo apt install python3 python3-venv python3-pip

# Créer le venv dans WSL
cd /mnt/c/snmp_project/Beta-SNMP
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## ✅ Vérifier que tout fonctionne

```powershell
# 1️⃣ Activer le venv
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
# Prompt DOIT commencer par (venv)

# 2️⃣ Vérifier pysnmp
python -c "import pysnmp; print('✅ pysnmp', pysnmp.__version__)"

# 3️⃣ Vérifier les imports async
python -c "from pysnmp.hlapi.v3arch.asyncio import get_cmd; print('✅ async API OK')"

# 4️⃣ Tester le mock agent
python collector/mock_snmp_agent.py --port 1161
# Doit afficher: "🎭 Mock SNMP Agent - SNMPv3 Démarré"
```

---

## 📍 Vérifier l'installation de Python

```powershell
# Voir la version et la source
python --version
python -c "import sys; print(sys.executable)"

# Doit afficher SOIT:
# ✅ C:\Users\Mathis\AppData\Local\Programs\Python\Python313\python.exe
# ✅ C:\Python313\python.exe

# ❌ PAS:
# ❌ C:\Program Files\WindowsApps\...\python.exe
```

---

## 💡 Commandes Rapides de Reset

```powershell
# Supprimer et recréer le venv proprement
cd C:\snmp_project\Beta-SNMP
Rm -Recurse -Force venv
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt

# Vérifier
python -m pip list | grep pysnmp
```

---

## ❌ Problèmes Supplémentaires

### PowerShell: "n'est pas reconnu" / Activation venv échoue

**Solution:**
```powershell
# En tant qu'Admin PowerShell:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Répondre "Y" pour Oui
```

---

### SNMP Timeout: "No SNMP response received before timeout"

**Cause:** Pas d'agent SNMP sur `127.0.0.1:1161`

**Solution:** Lancer le Mock Agent dans Terminal 1:

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

### Utiliser un Device SNMP réel

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

## ✅ Checklist Finale

- [ ] Python vient de **python.org** (pas Microsoft Store)
- [ ] `python --version` affiche la bonne version
- [ ] `Get-ExecutionPolicy` retourne `RemoteSigned`
- [ ] Prompt commence par `(venv)`
- [ ] `python -c "import pysnmp"` fonctionne
- [ ] Mock agent tourne et affiche les OIDs
- [ ] Collector collecte les OIDs avec succès

---

## 🆘 Besoin d'aide?

Vois le [README.md](./README.md) pour le démarrage complet.
