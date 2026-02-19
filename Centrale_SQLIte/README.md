# Centrale SQLite — SNMP Monitoring

Variante SQLite de la centrale SNMP. Ce dossier contient une application complète de monitoring SNMP déployable via un conteneur Docker unique, composée d'une API REST, d'une interface graphique web et d'une base de données SQLite embarquée.

---

## Programmes

### `snmp_database.py` — Couche base de données

Module Python qui gère toutes les interactions avec SQLite via le module standard `sqlite3`. Il crée et maintient trois tables :

- **`utilisateurs`** : comptes utilisateurs avec mots de passe hachés en SHA-512.
- **`paquets_recus`** : paquets SNMP capturés (v2c et v3), avec les VarBinds stockés en JSON.
- **`cles_API`** : clés d'API hachées en SHA-512 pour l'authentification Bearer.

Le module fournit les opérations CRUD complètes : ajout/vérification d'utilisateurs, insertion/recherche/statistiques de paquets SNMP, et gestion des clés API (génération, validation, révocation). La base SQLite est stockée dans un fichier unique (par défaut `/data/snmp.db` dans Docker).

### `snmp_api_improved.py` — API REST FastAPI

API REST tournant sur le port **8000** (HTTP). Tous les endpoints (sauf `/health`) requièrent un token Bearer. L'API expose :

- **Authentification** : login utilisateur (`POST /auth/login`).
- **Gestion utilisateurs** : création et listing (`POST /users/register`, `GET /users/list`).
- **Gestion des clés API** : création, listing et révocation.
- **Trames SNMP** : ajout de trames v2c et v3, consultation avec filtres, recherche avancée, statistiques.
- **Health check** : `GET /health` (sans authentification).

Lors de l'ajout d'une trame v2c, une alerte SMS est déclenchée en tâche de fond si le niveau de sécurité est CRITIQUE ou ELEVEE.

### `snmp_gui_web.py` — Interface graphique web (Flet)

Application web servie sur le port **12000** via Flet en mode navigateur. Elle lit directement la base SQLite (sans passer par l'API). L'interface comprend 5 sections :

- **Dashboard** : 7 cartes de statistiques (total, GET, SET, RESPONSE, REPORT, erreurs, alertes) + activité récente.
- **Traffic SNMP** : tableau paginé de tous les paquets avec filtres (IP source, type PDU, version SNMP, OID).
- **Emettre** : formulaire d'envoi de requêtes SNMP (GET, GETNEXT, SET, TRAP) en v2c ou v3.
- **Anomalies** : tableau des paquets avec alertes de sécurité + analyse IA via Ollama.
- **Statistiques** : 5 graphiques (répartition PDU, versions SNMP, top 10 sources, trafic 30 jours, top 10 OIDs).

### `snmp_sender.py` — Module d'émission SNMP

Module asynchrone utilisant pysnmp HLAPI pour envoyer des requêtes SNMP GET, GETNEXT, SET et TRAP. Supporte SNMPv2c (community string) et SNMPv3 (authentification SHA + chiffrement DES).

### `sms_alerter.py` — Alertes SMS Twilio

Module appelé en tâche de fond par l'API. Envoie un SMS via Twilio uniquement lorsqu'un paquet a un niveau d'alerte CRITIQUE ou ELEVEE. Nécessite les 4 variables Twilio configurées.

### `init_db.py` — Initialisation de la base

Script exécuté au démarrage du conteneur. Il crée le fichier SQLite et les tables si nécessaire, puis :
- Crée un utilisateur `admin` avec un mot de passe aléatoire si aucun utilisateur n'existe.
- Crée une première clé API si aucune n'existe.
- Les identifiants sont affichés **une seule fois** dans les logs du conteneur (`docker logs`).

---

## Installation et déploiement Docker

### Prérequis

- Docker installé.
- Le dépôt cloné localement.

### 1. Cloner le dépôt

```bash
git clone <URL_DU_REPO>
cd Beta-SNMP/Centrale_SQLite
```

### 2. Build de l'image

```bash
docker build -t snmp-centrale-sqlite .
```

### 3. Lancement du conteneur

**Lancement minimal** (sans alertes SMS ni analyse IA) :

```bash
docker run -d \
  --name centrale-sqlite \
  -p 8000:8000 \
  -p 12000:12000 \
  -v snmp_data:/data \
  snmp-centrale-sqlite
```

**Lancement complet** (avec toutes les options) :

```bash
docker run -d \
  --name centrale-sqlite \
  -p 8000:8000 \
  -p 12000:12000 \
  -v snmp_data:/data \
  -e TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -e TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -e TWILIO_FROM_NUMBER=+1234567890 \
  -e TWILIO_TO_NUMBER=+33612345678 \
  -e OLLAMA_ENDPOINT=http://votre-serveur:11434 \
  -e OLLAMA_MODEL=llama3.3:70b \
  snmp-centrale-sqlite
```

### Variables d'environnement

| Variable | Description | Défaut | Obligatoire |
|---|---|---|---|
| `DB_PATH` | Chemin du fichier SQLite | `/data/snmp.db` | Non |
| `LOG_DIR` | Répertoire des logs | `/data` | Non |
| `API_PORT` | Port de l'API | `8000` | Non |
| `GUI_PORT` | Port de la GUI | `12000` | Non |
| `TWILIO_ACCOUNT_SID` | SID du compte Twilio | — | Non (alertes SMS) |
| `TWILIO_AUTH_TOKEN` | Token d'auth Twilio | — | Non (alertes SMS) |
| `TWILIO_FROM_NUMBER` | Numéro expéditeur Twilio | — | Non (alertes SMS) |
| `TWILIO_TO_NUMBER` | Numéro destinataire SMS | — | Non (alertes SMS) |
| `OLLAMA_ENDPOINT` | URL du serveur Ollama | `http://openwebui.iutbeziers.fr:11434` | Non (analyse IA) |
| `OLLAMA_MODEL` | Modèle LLM à utiliser | `llama3.3:70b` | Non (analyse IA) |

### 4. Récupérer les identifiants

Au premier lancement, `init_db.py` génère un utilisateur admin et une clé API. Ces informations sont affichées **une seule fois** dans les logs :

```bash
docker logs centrale-sqlite
```

Cherchez les lignes contenant le mot de passe admin et la clé API. **Notez-les immédiatement**, elles ne seront plus affichées.

### 5. Vérifier le bon fonctionnement

```bash
# Health check de l'API
curl http://localhost:8000/health

# Accéder à la GUI
# Ouvrir http://localhost:12000 dans un navigateur
```

### Volume persistant

| Volume | Contenu |
|---|---|
| `snmp_data` (monté sur `/data`) | Base SQLite (`snmp.db`) + logs applicatifs |

Le volume `/data` contient à la fois la base de données et les fichiers de logs. Il est essentiel de le monter pour persister les données entre les redémarrages du conteneur.

### Arrêt et suppression

```bash
# Arrêter le conteneur
docker stop centrale-sqlite

# Supprimer le conteneur
docker rm centrale-sqlite

# Supprimer le volume (PERTE DE DONNEES)
docker volume rm snmp_data
```
