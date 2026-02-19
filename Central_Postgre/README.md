# Centrale PostgreSQL — SNMP Monitoring

Variante PostgreSQL de la centrale SNMP. Ce dossier contient une application complète de monitoring SNMP déployable via Docker, composée d'une API REST, d'une interface graphique web et d'une base de données PostgreSQL.

---

## Programmes

### `snmp_database_postgre.py` — Couche base de données

Module Python qui gère toutes les interactions avec PostgreSQL via `psycopg2`. Il crée et maintient trois tables :

- **`utilisateurs`** : comptes utilisateurs avec mots de passe hachés en SHA-512.
- **`paquets_recus`** : paquets SNMP capturés (v2c et v3), avec les VarBinds stockés en JSON.
- **`cles_API`** : clés d'API hachées en SHA-512 pour l'authentification Bearer.

Le module fournit les opérations CRUD complètes : ajout/vérification d'utilisateurs, insertion/recherche/statistiques de paquets SNMP, et gestion des clés API (génération, validation, révocation).

### `snmp_api_improved_postgre.py` — API REST FastAPI

API REST tournant sur le port **8000** (HTTP). Tous les endpoints (sauf `/health`) requièrent un token Bearer. L'API expose :

- **Authentification** : login utilisateur (`POST /auth/login`).
- **Gestion utilisateurs** : création et listing (`POST /users/register`, `GET /users/list`).
- **Gestion des clés API** : création, listing et révocation.
- **Trames SNMP** : ajout de trames v2c et v3, consultation avec filtres, recherche avancée, statistiques.
- **Health check** : `GET /health` (sans authentification).

Lors de l'ajout d'une trame v2c, une alerte SMS est déclenchée en tâche de fond si le niveau de sécurité est CRITIQUE ou ELEVEE.

### `snmp_gui_web.py` — Interface graphique web (Flet)

Application web servie sur le port **12000** via Flet en mode navigateur. Elle lit directement la base PostgreSQL (sans passer par l'API). L'interface comprend 5 sections :

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

Script exécuté au démarrage du conteneur. Il attend que PostgreSQL soit prêt, puis :
- Crée un utilisateur `admin` avec un mot de passe aléatoire si aucun utilisateur n'existe.
- Crée une première clé API si aucune n'existe.
- Les identifiants sont affichés **une seule fois** dans les logs du conteneur (`docker logs`).

### `Ajout_clé.py` — Générateur de clé API (CLI)

Petit script utilitaire pour ajouter manuellement une clé API depuis la ligne de commande (hors Docker).

---

## Installation et déploiement Docker

### Prérequis

- Docker et Docker Compose installés.
- Le dépôt cloné localement.

### 1. Cloner le dépôt

```bash
git clone <URL_DU_REPO>
cd Beta-SNMP/Central_Postgre
```

### 2. Configurer l'environnement

Copier le fichier d'exemple et le remplir :

```bash
cp .env.example .env
```

Editer `.env` avec vos valeurs :

| Variable | Description | Obligatoire |
|---|---|---|
| `POSTGRES_DB` | Nom de la base PostgreSQL | Oui |
| `POSTGRES_USER` | Utilisateur PostgreSQL | Oui |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL | Oui |
| `TWILIO_ACCOUNT_SID` | SID du compte Twilio | Non (alertes SMS) |
| `TWILIO_AUTH_TOKEN` | Token d'auth Twilio | Non (alertes SMS) |
| `TWILIO_FROM_NUMBER` | Numéro expéditeur Twilio | Non (alertes SMS) |
| `TWILIO_TO_NUMBER` | Numéro destinataire SMS | Non (alertes SMS) |
| `OLLAMA_ENDPOINT` | URL du serveur Ollama | Non (analyse IA) |
| `OLLAMA_MODEL` | Modèle LLM à utiliser | Non (analyse IA) |

**Variables supplémentaires pour `docker-compose_full.yml` (Traefik)** :

| Variable | Description |
|---|---|
| `DOMAIN` | Nom de domaine principal (ex: `example.com`) |
| `API_SUBDOMAIN` | Sous-domaine de l'API (défaut : `api`) |
| `CERTBOT_EMAIL` | Email pour Let's Encrypt |
| `OVH_APPLICATION_KEY` | Clé application OVH (DNS challenge) |
| `OVH_APPLICATION_SECRET` | Secret application OVH |
| `OVH_CONSUMER_KEY` | Clé consommateur OVH |

### 3. Build et lancement

**Déploiement simple** (accès direct aux ports) :

```bash
docker compose up -d --build
```

Cela utilise `docker-compose.yml` et lance :
- PostgreSQL sur le port `5432`
- L'API sur le port `8000`
- La GUI sur le port `12000`

**Déploiement avec reverse-proxy Traefik** (HTTPS automatique) :

```bash
docker compose -f docker-compose_full.yml up -d --build
```

Cela ajoute Traefik qui gère le TLS via Let's Encrypt (DNS challenge OVH) :
- `https://api.<DOMAIN>` → API (port 8000)
- `https://<DOMAIN>` → GUI (port 12000)
- Redirection HTTP → HTTPS automatique

### 4. Récupérer les identifiants

Au premier lancement, `init_db.py` génère un utilisateur admin et une clé API. Ces informations sont affichées **une seule fois** dans les logs :

```bash
docker logs centrale-postgre
```

Cherchez les lignes contenant le mot de passe admin et la clé API. **Notez-les immédiatement**, elles ne seront plus affichées.

### 5. Vérifier le bon fonctionnement

```bash
# Health check de l'API
curl http://localhost:8000/health

# Accéder à la GUI
# Ouvrir http://localhost:12000 dans un navigateur
```

### Volumes persistants

| Volume | Contenu |
|---|---|
| `postgres_data` | Données PostgreSQL |
| `centrale_logs` | Logs applicatifs (`/data`) |
| `traefik_certs` | Certificats Let's Encrypt (déploiement full uniquement) |

### Arrêt et suppression

```bash
# Arrêter les conteneurs
docker compose down

# Arrêter et supprimer les volumes (PERTE DE DONNEES)
docker compose down -v
```
