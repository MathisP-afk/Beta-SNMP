# 🚢 DOCKER POSTGRESQL - GUIDE WINDOWS

**Setup PostgreSQL en container Docker en 2 minutes**

---

## 👋 PRÉREQUIS

- ✅ Docker Desktop installé sur Windows
- ✅ Git clone branch `snmpv3-collector-v2`
- ✅ PowerShell

**Pas besoin d'installer PostgreSQL nativement!**

---

## 🚀 LANCER POSTGRESQL EN DOCKER (2 MIN)

### Step 1: Placer-toi dans le dossier du projet

```powershell
cd C:\snmp_project\Beta-SNMP
ls  # Doit voir: docker-compose.yml, init.sql
```

### Step 2: Démarrer le container PostgreSQL

```powershell
# Depuis le dossier Beta-SNMP
docker-compose up -d

# Résultat:
# [+] Running 1/1
#  ✓ Container snmp_postgres  Started
```

### Step 3: Vérifier que PostgreSQL marche

```powershell
# Vérifier l'état du container
docker-compose ps

# Résultat:
# NAME             STATUS
# snmp_postgres   Up 2 seconds
```

---

## ✅ VÉRIFIER LA CONNEXION

### Méthode 1: Depuis PowerShell (avec psql)

```powershell
# Se connecter à la BDD
psql -U snmp_user -h localhost -d snmp_db

# Une fois dedans:
\dt  # Voir les tables créées
\q   # Quitter
```

**Résultat attendu:**
```
              List of relations
 Schema |       Name        | Type  |  Owner
--------+-------------------+-------+----------
 public | alerts            | table | snmp_user
 public | collectors        | table | snmp_user
 public | interface_data    | table | snmp_user
 public | snmp_data         | table | snmp_user
 public | system_info       | table | snmp_user
```

### Méthode 2: Accéder au container directement

```powershell
# Ouvrir une session interactive dans le container
docker exec -it snmp_postgres psql -U snmp_user -d snmp_db

# Dans psql:
SELECT * FROM collectors;
\q
```

**Résultat attendu:**
```
 id |   name    | ip_address  | port | snmp_user | ...
----+-----------+-------------+------+-----------+----
  1 | SG250-Test| 192.168.1.39| 161  | Alleria_W | ...
```

---

## 🕌 COMMANDES UTILES DOCKER

### Démarrer PostgreSQL

```powershell
docker-compose up -d
```

### Arrêter PostgreSQL (mais garde les données)

```powershell
docker-compose down
```

### Arrêter ET supprimer les données (ATTENTION!)

```powershell
docker-compose down -v
```

### Voir les logs du container

```powershell
docker-compose logs -f postgres

# Quitter les logs: Ctrl+C
```

### Redémarrer PostgreSQL

```powershell
docker-compose restart postgres
```

### Vérifier l'état

```powershell
docker-compose ps
```

---

## 📋 ARCHITECTURE

```
Ta machine Windows
    ↓
 Docker Desktop
    ↓
Container snmp_postgres (Port 5432)
    ↓
Volume postgres_data/ (persist les données)
    ↓
Fichier init.sql (crée les tables automatiquement)
```

---

## 💪 CONFIGURATION DU `.env`

Pour utiliser le Docker PostgreSQL, ta `.env` doit avoir:

```bash
# ===== DATABASE (DOCKER) =====
DB_HOST=localhost
DB_PORT=5432
DB_USER=snmp_user
DB_PASSWORD=snmp_password_secure_123
DB_NAME=snmp_db
```

**Très important:** `DB_HOST=localhost` car le container s'écoute sur 127.0.0.1:5432!

---

## 🆘 TROUBLESHOOTING

### ❌ "docker: command not found"

- Docker Desktop n'est pas installé ou pas dans le PATH
- Installer depuis: https://www.docker.com/products/docker-desktop
- Redémarrer PowerShell après installation

### ❌ "Port 5432 is already allocated"

Un autre container PostgreSQL tourne sur le port 5432:

```powershell
# Voir les containers actifs
docker ps

# Arrêter tous les containers PostgreSQL
docker stop <CONTAINER_ID>

# Ou simplement:
docker-compose down
```

### ❌ "Cannot connect to the Docker daemon"

- Docker Desktop n'est pas lancé
- Lance Docker Desktop depuis le menu Windows
- Attends qu'il soit completément démarré

### ❌ "Connection refused" depuis psql

```powershell
# Vérifier que le container est vraiment actif
docker-compose ps

# Vérifier les logs
docker-compose logs postgres

# Redemarrer si besoin
docker-compose restart postgres
```

### ❌ "Tables not created"

L'init.sql n'a pas été exécuté. Solution:

```powershell
# Supprimer le volume (ATTENTION: perte de données!)
docker-compose down -v

# Relancer
docker-compose up -d
```

---

## ⏹️ ARRÊTER POSTGRESQL

```powershell
# Simple (les données restent)
docker-compose down

# Avec suppression des données (ATTENTION!)
docker-compose down -v
```

**Les données seront préservées** dans le volume `postgres_data/` même si tu arrêtes le container.

---

## 📁 OD' SONT LES DONNÉES?

Sur Windows, le volume Docker est stocké ici:

```
C:\Users\<TON_USER>\AppData\Local\Docker\wsl\data\ext4.vhdx
```

Pas besoin de t'en occuper! Docker gère tout automatiquement.

---

## 📚 NEXT STEPS

1. ✅ Docker PostgreSQL lancé
2. ✅ Tables créées automatiquement (init.sql)
3. ⏳ Lancer l'API + Collector (voir `QUICKSTART_INFRASTRUCTURE.md`)

---

## 📃 RÉSUMÉ

| Commande | Action |
|----------|--------|
| `docker-compose up -d` | Démarrer PostgreSQL |
| `docker-compose down` | Arrêter (données préservées) |
| `docker-compose ps` | Vérifier l'état |
| `docker-compose logs -f postgres` | Voir les logs |
| `psql -U snmp_user -h localhost -d snmp_db` | Se connecter à la BDD |

**C'est tout! Tu es prêt à lancer l'infrastructure complète!** 🚀

