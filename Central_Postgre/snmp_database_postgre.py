import os
from dotenv import load_dotenv
load_dotenv()
import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
import secrets

class SNMPDatabase:
    """
    Classe pour gérer la base de données SNMP avec tables utilisateurs et paquets reçus
    Version adaptée pour PostgreSQL
    """
    
    # On adapte les arguments par défaut pour coller à ton Docker Compose
    # Les credentials sont lues depuis les variables d'environnement (fichier .env)
    def __init__(self,
                 host: str = os.environ.get("POSTGRES_HOST", "localhost"),
                 port: int = int(os.environ.get("POSTGRES_PORT", "5432")),
                 database: str = os.environ.get("POSTGRES_DB", "snmpdatabase"),
                 user: str = os.environ.get("POSTGRES_USER", "SylvAdminBDD"),
                 password: str = os.environ.get("POSTGRES_PASSWORD", ""),
                 log_file: str = "logs_"+datetime.now().strftime('%d-%m-%Y')+".log"):
        """
        Initialise la connexion à la base de données PostgreSQL
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.log_file = log_file
        self.connection = None
        
        self.connect()
        self.initialize_database()
    
    def connect(self):
        """Établit la connexion à la base de données PostgreSQL"""
        try:
            # Utilisation des arguments nommés pour gérer proprement 
            # les caractères spéciaux dans le user/password
            self.connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.database,
                user=self.user,
                password=self.password
            )
            
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + "] - Connexion à la base de données réussie.\n")
        except Exception as e:
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Erreur de connexion à la base de données : {e}.\n")
            raise
    
    def close(self):
        """Ferme la connexion à la base de données"""
        if self.connection:
            self.connection.close()
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Fermeture de la connexion à la base de données - Au revoir!\n")
    
    def initialize_database(self):
        """Crée les tables nécessaires si elles n'existent pas"""
        cursor = self.connection.cursor()
        
        # Table des utilisateurs
        # Note: SERIAL remplace AUTOINCREMENT, BOOLEAN remplace le 0/1 int
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS utilisateurs (
                id SERIAL PRIMARY KEY,

                -- Informations d'authentification
                nom_utilisateur TEXT UNIQUE NOT NULL,
                mot_de_passe_hash TEXT NOT NULL,
                        
                -- Informations de logging
                date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                derniere_connexion TIMESTAMP,
                        
                -- Si l'user est activé ou non
                actif BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Table des paquets SNMP reçus
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS paquets_recus (
                id SERIAL PRIMARY KEY,
                
                -- Informations Réseau de base
                timestamp_reception TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_snmp TEXT NOT NULL,
                adresse_source TEXT NOT NULL,
                port_source INTEGER NOT NULL,
                adresse_dest TEXT NOT NULL,
                port_dest INTEGER NOT NULL,
                taille_paquet INTEGER,

                -- Mécanique SNMP
                type_pdu TEXT,
                request_id INTEGER,
                error_status TEXT,
                error_index INTEGER,
                
                -- Contenu
                communaute TEXT,
                oid_racine TEXT,
                contenu_json TEXT,
                
                -- Spécifique SNMPv3
                agent_snmp TEXT,
                utilisateur_v3 TEXT,
                niveau_securite TEXT,
                contexte_v3 TEXT,
                engine_id TEXT,
                msg_id INTEGER
            )
        ''')
        
        # Table des clés API
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cles_API (
                id SERIAL PRIMARY KEY,
                cle TEXT UNIQUE NOT NULL,
                activee BOOLEAN DEFAULT TRUE,
                description TEXT NOT NULL,
                date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.connection.commit()
        with open(self.log_file, 'a', encoding='utf-8') as lf:
            lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Initialisation de la base de données PostgreSQL - Bonne aventure SNMP!\n")
    
    def hash_sha512(self, text: str) -> str:
        """Chiffre un texte en SHA512"""
        return hashlib.sha512(text.encode('utf-8')).hexdigest()
    
    # GESTION DES UTILISATEURS
    def ajouter_utilisateur(self, nom_utilisateur: str, mot_de_passe: str) -> bool:
        """Ajoute un nouvel utilisateur"""
        cursor = self.connection.cursor()
        
        try:
            mdp_hash = self.hash_sha512(mot_de_passe)
            
            # Syntax PostgreSQL : %s au lieu de ?
            # RETURNING id : nécessaire car Postgres ne supporte pas lastrowid
            cursor.execute('''
                INSERT INTO utilisateurs (nom_utilisateur, mot_de_passe_hash)
                VALUES (%s, %s)
                RETURNING id
            ''', (nom_utilisateur, mdp_hash))
            
            new_id = cursor.fetchone()[0]
            self.connection.commit()
            
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Utilisateur ajouté avec succès (ID: {new_id})\n")
            return True
            
        except psycopg2.IntegrityError:
            self.connection.rollback() # Important en Postgres après une erreur
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + "] - Erreur d'ajout d'un utilisateur - Utilisateur déjà existant.\n")
            return False
        except Exception as e:
            self.connection.rollback()
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] -Erreur d'ajout d'un utilisateur - {e}.\n")
            return False
    
    def verifier_utilisateur(self, nom_utilisateur: str, mot_de_passe: str) -> bool:
        """Vérifie les identifiants d'un utilisateur"""
        cursor = self.connection.cursor()
        
        mdp_hash = self.hash_sha512(mot_de_passe)
        
        cursor.execute('''
            SELECT id FROM utilisateurs 
            WHERE nom_utilisateur = %s AND mot_de_passe_hash = %s AND actif = TRUE
        ''', (nom_utilisateur, mdp_hash))
        
        result = cursor.fetchone()
        
        if result:
            cursor.execute('''
                UPDATE utilisateurs 
                SET derniere_connexion = CURRENT_TIMESTAMP 
                WHERE id = %s
            ''', (result[0],))
            self.connection.commit()
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Connection de l'utilisateur {nom_utilisateur}.\n")
            return True
        
        return False
    
    def lister_utilisateurs(self) -> List[Dict]:
        """Retourne la liste des utilisateurs"""
        # RealDictCursor permet de récupérer les résultats sous forme de dictionnaire (comme sqlite3.Row)
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        cursor.execute('''
            SELECT id, nom_utilisateur, date_creation, derniere_connexion, actif 
            FROM utilisateurs 
            WHERE actif = TRUE
        ''')
        
        return [dict(row) for row in cursor.fetchall()]
    
    # GESTION DES PAQUETS SNMP
    def ajouter_paquet_snmp(self, 
                            version_snmp: str,
                            adresse_source: str,
                            port_source: int,
                            adresse_dest: str,
                            port_dest: int,
                            contenu: Dict,
                            request_id: int,
                            error_status: str = "0",
                            error_index: int = 0,
                            type_pdu: str = None,
                            communaute: str = None,
                            oid_racine: str = None,
                            agent_snmp: str = None,
                            utilisateur_v3: str = None,
                            niveau_securite: str = None,
                            contexte_v3: str = None,
                            engine_id: str = None,
                            msg_id: int = None      
                           ) -> bool:
        """Ajoute un paquet SNMP reçu dans la base de données"""
        cursor = self.connection.cursor()
        
        try:
            contenu_json = json.dumps(contenu, ensure_ascii=False, indent=2)
            taille_paquet = len(contenu_json.encode('utf-8'))
            
            cursor.execute('''
                INSERT INTO paquets_recus (
                    version_snmp, adresse_source, port_source, adresse_dest,
                    port_dest, taille_paquet, type_pdu, request_id, error_status,
                    error_index, communaute, oid_racine, contenu_json,
                    agent_snmp, utilisateur_v3, niveau_securite, contexte_v3, engine_id,
                    msg_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (version_snmp, adresse_source, port_source, adresse_dest, port_dest,
                  taille_paquet, type_pdu, request_id, error_status, error_index,
                  communaute, oid_racine, contenu_json, agent_snmp, utilisateur_v3, niveau_securite,
                  contexte_v3, engine_id, msg_id
                  ))
            
            new_id = cursor.fetchone()[0]
            self.connection.commit()
            
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                 lf.write(f"[{datetime.now().strftime('%d-%m-%Y_%H:%M:%S')}] - Paquet SNMP ajouté (ID: {new_id})\n")
            return True
            
        except Exception as e:
            self.connection.rollback()
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write(f"[{datetime.now().strftime('%d-%m-%Y_%H:%M:%S')}] - ERREUR ajout paquet : {e}\n")
            return False
    
    def lister_paquets_snmp(self, limite: int = 100, version_snmp: str = None) -> List[Dict]:
        """Retourne la liste des paquets SNMP reçus"""
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        
        if version_snmp:
            cursor.execute('''
                SELECT * FROM paquets_recus 
                WHERE version_snmp = %s
                ORDER BY timestamp_reception DESC 
                LIMIT %s
            ''', (version_snmp, limite))
        else:
            cursor.execute('''
                SELECT * FROM paquets_recus 
                ORDER BY timestamp_reception DESC 
                LIMIT %s
            ''', (limite,))
        
        paquets = []
        for row in cursor.fetchall():
            paquet = dict(row)
            if paquet['contenu_json']:
                try:
                    paquet['contenu'] = json.loads(paquet['contenu_json'])
                except:
                    paquet['contenu'] = {}
            paquets.append(paquet)
        
        return paquets
    
    def statistiques_paquets(self) -> Dict[str, Any]:
        """Retourne les statistiques des paquets SNMP"""
        cursor = self.connection.cursor()
        
        stats = {}
        
        # Nombre total de paquets
        cursor.execute('SELECT COUNT(*) as total FROM paquets_recus')
        stats['total_paquets'] = cursor.fetchone()[0]
        
        # Répartition par version
        cursor.execute('''
            SELECT version_snmp, COUNT(*) as count 
            FROM paquets_recus 
            GROUP BY version_snmp
        ''')
        stats['par_version'] = dict(cursor.fetchall())
        
        # Top 5 des sources
        cursor.execute('''
            SELECT adresse_source, COUNT(*) as count 
            FROM paquets_recus 
            GROUP BY adresse_source 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        stats['top_sources'] = dict(cursor.fetchall())
        
        # Paquets par jour (7 derniers jours)
        # Syntaxe Postgres pour les dates : CURRENT_TIMESTAMP - INTERVAL
        cursor.execute('''
            SELECT DATE(timestamp_reception) as jour, COUNT(*) as count 
            FROM paquets_recus 
            WHERE timestamp_reception >= CURRENT_TIMESTAMP - INTERVAL '7 days'
            GROUP BY DATE(timestamp_reception)
            ORDER BY jour DESC
        ''')
        # Conversion explicite des objets Date en string pour JSON
        stats['derniers_7_jours'] = {str(row[0]): row[1] for row in cursor.fetchall()}
        
        return stats
    
    def rechercher_paquets(self, 
                           adresse_source: str = None,
                           adresse_dest: str = None,
                           version_snmp: str = None,
                           oid_racine: str = None,
                           date_debut: str = None,
                           date_fin: str = None) -> List[Dict]:
        """Recherche des paquets selon des critères"""
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        
        # 1=1 est toujours vrai, pratique pour chaîner les AND
        query = "SELECT * FROM paquets_recus WHERE TRUE"
        params = []
        
        if adresse_source:
            query += " AND adresse_source = %s"
            params.append(adresse_source)
        
        if adresse_dest:
            query+= " AND adresse_dest = %s"
            params.append(adresse_dest)
        
        if version_snmp:
            query += " AND version_snmp = %s"
            params.append(version_snmp)
        
        if oid_racine:
            query += " AND oid_racine LIKE %s"
            params.append(f"%{oid_racine}%")
        
        if date_debut:
            query += " AND DATE(timestamp_reception) >= %s"
            params.append(date_debut)
        
        if date_fin:
            query += " AND DATE(timestamp_reception) <= %s"
            params.append(date_fin)
        
        query += " ORDER BY timestamp_reception DESC"
        
        cursor.execute(query, params)
        
        paquets = []
        for row in cursor.fetchall():
            paquet = dict(row)
            if paquet['contenu_json']:
                try:
                    paquet['contenu'] = json.loads(paquet['contenu_json'])
                except:
                    paquet['contenu'] = {}
            paquets.append(paquet)
        
        return paquets

    def generer_cle_api(self) -> str:
        """Génère une clé API unique"""
        cle_api = secrets.token_urlsafe(48)
        return cle_api

    def ajouter_cle_api(self, description = "/") -> Optional[str]:
        """Ajoute une nouvelle clé API"""
        cursor = self.connection.cursor()
        
        try:
            cle = self.generer_cle_api()
            cle_hash = self.hash_sha512(cle)
            
            cursor.execute('''
                INSERT INTO cles_API (cle, activee, description)
                VALUES (%s, TRUE, %s)
                RETURNING id
            ''', (cle_hash, description,))
            
            new_id = cursor.fetchone()[0]
            self.connection.commit()
            
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Création de la clé API - ID: {new_id}.\n")
            return cle
            
        except Exception as e:
            self.connection.rollback()
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Erreur lors de la création d'une clé API - {e}.\n")
            return None

    def lister_cles_api(self, actives_seulement: bool = False) -> List[Dict]:
        """Liste les clés API"""
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        
        if actives_seulement:
            cursor.execute('''
                SELECT id, activee, description, date_creation 
                FROM cles_API 
                WHERE activee = TRUE
                ORDER BY date_creation DESC
            ''')
        else:
            cursor.execute('''
                SELECT id, cle, activee, description, date_creation 
                FROM cles_API
                ORDER BY date_creation DESC
            ''')
        
        return [dict(row) for row in cursor.fetchall()]

    def valider_cle_api(self, cle: str) -> bool:
        """Vérifie si une clé API existe et est activée"""
        cursor = self.connection.cursor()
        cle_hash = self.hash_sha512(cle)
        
        cursor.execute('''
            SELECT id FROM cles_API 
            WHERE cle = %s AND activee = TRUE
        ''', (cle_hash,))
        
        return cursor.fetchone() is not None
    
    def desactiver_cle_api_par_id(self, id: int) -> bool:
        """Désactive une clé API"""
        cursor = self.connection.cursor()
        
        cursor.execute('''
            UPDATE cles_API 
            SET activee = FALSE 
            WHERE ID = %s
        ''', (id,))
        
        self.connection.commit()
        
        if cursor.rowcount > 0:
            with open(self.log_file, 'a', encoding='utf-8') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Clé API ID {id} désactivée avec succès.\n")
            return True        
        return False


# Exemple d'utilisation
def exemple_utilisation():
    print("🚀 === EXEMPLE D'UTILISATION DE LA BASE DE DONNÉES SNMP (POSTGRESQL) ===")
    
    # Pas besoin de passer d'arguments si tu utilises les valeurs par défaut
    # définies dans le __init__ qui correspondent à ton docker-compose
    try:
        db = SNMPDatabase()
    except Exception:
        print("❌ Impossible de se connecter. Vérifie que le conteneur Docker est lancé.")
        return

    print("\n📝 === GESTION DES UTILISATEURS ===")
    db.ajouter_utilisateur("admin", "motdepasse123")
    db.ajouter_utilisateur("moniteur", "snmp2024!")
    
    print(f"✅ Connexion admin: {db.verifier_utilisateur('admin', 'motdepasse123')}")
    print(f"❌ Connexion invalide: {db.verifier_utilisateur('admin', 'mauvaismdp')}")
    
    utilisateurs = db.lister_utilisateurs()
    print(f"👥 Nombre d'utilisateurs: {len(utilisateurs)}")
    
    print("\n📦 === GESTION DES PAQUETS SNMP ===")
    
    # Paquet SNMP v2c
    contenu_v2c = {
        "varbinds": [
            {"oid": "1.3.6.1.2.1.1.1.0", "type": "OCTET_STRING", "value": "Linux router 5.4.0"}
        ]
    }
    
    db.ajouter_paquet_snmp(
        version_snmp="v2c",
        adresse_source="192.168.1.100",
        port_source=161,
        adresse_dest="192.168.2.100",
        port_dest=162,
        contenu=contenu_v2c,
        request_id=12345,
        error_index=0,
        communaute="public",
        oid_racine="1.3.6.1.2.1.1.1.0",
        type_pdu="GetResponse"
    )
    
    # Paquet SNMP v3
    contenu_v3 = {
        "request_id": 67890,
        "error_status": 0,
        "error_index": 0,
        "varbinds": [
            {"oid": "1.3.6.1.2.1.1.3.0", "type": "TimeTicks", "value": 1234567}
        ]
    }
    
    db.ajouter_paquet_snmp(
        version_snmp="v3",
        adresse_source="10.0.1.50",
        port_source=161,
        adresse_dest="172.16.55.98",
        port_dest=188,
        contenu=contenu_v3,
        request_id=contenu_v3["request_id"],
        error_status=str(contenu_v3["error_status"]),
        error_index=contenu_v3["error_index"],
        oid_racine="1.3.6.1.2.1.1.3.0",
        type_pdu="GetRequest",
        contexte_v3="default",
        niveau_securite="authPriv",
        utilisateur_v3="snmpuser"
    )
    
    db.ajouter_cle_api()

    print("\n📊 === STATISTIQUES ===")
    stats = db.statistiques_paquets()
    # default=str est nécessaire pour gérer les objets datetime/date de Postgres
    print(f"📈 Statistiques: {json.dumps(stats, indent=2, ensure_ascii=False, default=str)}")
    
    print("\n🔍 === RECHERCHE DE PAQUETS ===")
    paquets_v3 = db.rechercher_paquets(version_snmp="v3")
    print(f"🔒 Paquets SNMP v3 trouvés: {len(paquets_v3)}")

    print("\n❤️ === CLÉS API ===")
    cles_apis = db.lister_cles_api()
    # On imprime juste le nombre pour ne pas spammer, car cles_apis contient des datetimes
    print(f"❤️ Nombre de clés API : {len(cles_apis)}")
    
    paquets_recents = db.lister_paquets_snmp(limite=5)
    print(f"⏰ Paquets récents: {len(paquets_recents)}")
    
    db.close()
    print("\n✅ === EXEMPLE TERMINÉ AVEC SUCCÈS ===")

if __name__ == "__main__":
    exemple_utilisation()