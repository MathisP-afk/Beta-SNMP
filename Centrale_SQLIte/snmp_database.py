import sqlite3
import hashlib
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
import secrets

class SNMPDatabase:
    """
    Classe pour gérer la base de données SNMP avec tables utilisateurs et paquets reçus
    """
    
    def __init__(self, db_path: str = None, log_file: str = None):
        if db_path is None:
            db_path = os.environ.get("DB_PATH", "exemple_snmp.db")
        if log_file is None:
            log_dir = os.environ.get("LOG_DIR", ".")
            log_file = os.path.join(log_dir, "logs_"+datetime.now().strftime('%d-%m-%Y')+".log")
        """
        Initialise la connexion à la base de données
        
        Args:
            db_path (str): Chemin vers le fichier de base de données
        """
        self.db_path = db_path
        self.log_file = log_file
        self.connection = None
        self.connect()
        self.initialize_database()
    
    def connect(self):
        """Établit la connexion à la base de données SQLite"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row  # Pour accéder aux colonnes par nom
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + "] - Connexion à la base de données réussie.\n")
        except Exception as e:
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Erreur de connexion à la base de données : {e}.\n")
            raise
    
    def close(self):
        """Ferme la connexion à la base de données"""
        if self.connection:
            self.connection.close()
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Fermeture de la connexion à la base de données - Au revoir!\n")
    
    def initialize_database(self):
        """Crée les tables nécessaires si elles n'existent pas"""
        cursor = self.connection.cursor()
        
        # Table des utilisateurs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS utilisateurs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                -- Informations d'authentification
                nom_utilisateur TEXT UNIQUE NOT NULL,
                mot_de_passe_hash TEXT NOT NULL,
                       
                -- Informations de logging
                date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                derniere_connexion TIMESTAMP,
                       
                -- Si l'user est activé ou non
                actif BOOLEAN DEFAULT 1
            )
        ''')
        
        # Table des paquets SNMP reçus
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS paquets_recus (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                
                -- Informations Réseau de base
                timestamp_reception TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_snmp TEXT NOT NULL,
                adresse_source TEXT NOT NULL,
                port_source INTEGER NOT NULL,
                adresse_dest TEXT NOT NULL,
                port_dest INTEGER NOT NULL,
                taille_paquet INTEGER,

                -- Mécanique SNMP (Critique pour stats & erreurs)
                type_pdu TEXT,                   -- GET, GETNEXT, RESPONSE, TRAP...
                request_id INTEGER,              -- INDISPENSABLE pour lier requête/réponse
                error_status TEXT,               -- INDISPENSABLE pour les stats d'erreurs (0=noError)
                error_index INTEGER,             -- Quel OID a causé l'erreur ?
                
                -- Contenu
                communaute TEXT,                 -- Pour v1/v2c
                oid_racine TEXT,                 -- Le premier OID (utile pour indexation rapide)
                contenu_json TEXT,               -- Stockage complet des VarBinds
                
                -- Spécifique SNMPv3
                agent_snmp TEXT,
                utilisateur_v3 TEXT,
                niveau_securite TEXT,            -- noAuthNoPriv, authNoPriv, authPriv
                contexte_v3 TEXT,
                engine_id TEXT,                  -- Important pour l'identification unique v3
                msg_id INTEGER                   -- Detection de message v3
            )
        ''')
        
        # Table des clés API valides ou non
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cles_API (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cle TEXT UNIQUE NOT NULL,
                activee BOOLEAN DEFAULT 1,
                description TEXT NOT NULL,
                date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.connection.commit()
        with open(self.log_file, 'a') as lf:
            lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Initialisation de la base de données SQLite - Bonne aventure SNMP!\n")
    
    def hash_sha512(self, text: str) -> str:
        """
        Chiffre un texte en SHA512
        
        Args:
            text (str): Texte à chiffrer
            
        Returns:
            str: Hash SHA512 en hexadécimal
        """
        return hashlib.sha512(text.encode('utf-8')).hexdigest()
    
    # GESTION DES UTILISATEURS
    def ajouter_utilisateur(self, nom_utilisateur: str, mot_de_passe: str) -> bool:
        """
        Ajoute un nouvel utilisateur dans la base de données
        
        Args:
            nom_utilisateur (str): Nom d'utilisateur en clair
            mot_de_passe (str): Mot de passe en clair
            
        Returns:
            bool: True si ajouté avec succès, False sinon
        """
        cursor = self.connection.cursor()
        
        try:
            mdp_hash = self.hash_sha512(mot_de_passe)
            
            cursor.execute('''
                INSERT INTO utilisateurs (nom_utilisateur, mot_de_passe_hash)
                VALUES (?, ?)
            ''', (nom_utilisateur, mdp_hash))
            
            self.connection.commit()
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Utilisateur ajouté avec succès à la base (ID: {cursor.lastrowid})\n")
            return True
            
        except sqlite3.IntegrityError:
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + "] - Erreur d'ajout d'un utilisateur - Utilisateur déjà existant.\n")
            return False
        except Exception as e:
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] -Erreur d'ajout d'un utilisateur - {e}.\n")
            return False
    
    def verifier_utilisateur(self, nom_utilisateur: str, mot_de_passe: str) -> bool:
        """
        Vérifie les identifiants d'un utilisateur
        
        Args:
            nom_utilisateur (str): Nom d'utilisateur en clair
            mot_de_passe (str): Mot de passe en clair
            
        Returns:
            bool: True si identifiants valides, False sinon
        """
        cursor = self.connection.cursor()
        
        mdp_hash = self.hash_sha512(mot_de_passe)
        
        cursor.execute('''
            SELECT id FROM utilisateurs 
            WHERE nom_utilisateur = ? AND mot_de_passe_hash = ? AND actif = 1
        ''', (nom_utilisateur, mdp_hash))
        
        result = cursor.fetchone()
        
        if result:
            # Mettre à jour la dernière connexion
            cursor.execute('''
                UPDATE utilisateurs 
                SET derniere_connexion = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (result[0],))
            self.connection.commit()
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Connection de l'utilisateur {nom_utilisateur}.\n")
            return True
        
        return False
    
    def lister_utilisateurs(self) -> List[Dict]:
        """
        Retourne la liste des utilisateurs (sans les hashes)
        
        Returns:
            List[Dict]: Liste des utilisateurs avec leurs métadonnées
        """
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT id, nom_utilisateur, date_creation, derniere_connexion, actif 
            FROM utilisateurs 
            WHERE actif = 1
        ''')
        
        return [dict(row) for row in cursor.fetchall()]
    
    # GESTION DES PAQUETS SNMP
    def ajouter_paquet_snmp(self, 
                            version_snmp: str,
                            adresse_source: str,
                            port_source: int,
                            adresse_dest: str,
                            port_dest: int,
                            contenu: Dict,          # <--- AJOUTÉ (C'était manquant)
                            request_id: int,        # Argument critique
                            error_status: str = "0", # Valeur par défaut pour éviter les crashs
                            error_index: int = 0,
                            type_pdu: str = None,
                            communaute: str = None,
                            oid_racine: str = None,
                            agent_snmp: str = None,
                            utilisateur_v3: str = None,
                            niveau_securite: str = None,
                            contexte_v3: str = None,
                            engine_id: str = None,  # Mis en optionnel car pour SNMPv3
                            msg_id: int = None      
                           ) -> bool:
        """
        Ajoute un paquet SNMP reçu dans la base de données
        """
        cursor = self.connection.cursor()
        
        try:
            # Conversion du dictionnaire en JSON texte pour stockage
            contenu_json = json.dumps(contenu, ensure_ascii=False, indent=2)
            # Calcul automatique de la taille (plus fiable que de le demander en argument)
            taille_paquet = len(contenu_json.encode('utf-8'))
            
            cursor.execute('''
                INSERT INTO paquets_recus (
                    version_snmp, adresse_source, port_source, adresse_dest,
                    port_dest, taille_paquet, type_pdu, request_id, error_status,
                    error_index, communaute, oid_racine, contenu_json,
                    agent_snmp, utilisateur_v3, niveau_securite, contexte_v3, engine_id,
                    msg_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (version_snmp, adresse_source, port_source, adresse_dest, port_dest,
                  taille_paquet, type_pdu, request_id, error_status, error_index,
                  communaute, oid_racine, contenu_json, agent_snmp, utilisateur_v3, niveau_securite,
                  contexte_v3, engine_id, msg_id
                  ))
            
            self.connection.commit()
            # Logging simplifié
            with open(self.log_file, 'a') as lf:
                 lf.write(f"[{datetime.now().strftime('%d-%m-%Y_%H:%M:%S')}] - Paquet SNMP ajouté (ID: {cursor.lastrowid})\n")
            return True
            
        except Exception as e:
            with open(self.log_file, 'a') as lf:
                lf.write(f"[{datetime.now().strftime('%d-%m-%Y_%H:%M:%S')}] - ERREUR ajout paquet : {e}\n")
            return False
    
    def lister_paquets_snmp(self, limite: int = 100, version_snmp: str = None) -> List[Dict]:
        """
        Retourne la liste des paquets SNMP reçus
        
        Args:
            limite (int): Nombre maximum de paquets à retourner
            version_snmp (str, optional): Filtrer par version SNMP
            
        Returns:
            List[Dict]: Liste des paquets SNMP
        """
        cursor = self.connection.cursor()
        
        if version_snmp:
            cursor.execute('''
                SELECT * FROM paquets_recus 
                WHERE version_snmp = ?
                ORDER BY timestamp_reception DESC 
                LIMIT ?
            ''', (version_snmp, limite))
        else:
            cursor.execute('''
                SELECT * FROM paquets_recus 
                ORDER BY timestamp_reception DESC 
                LIMIT ?
            ''', (limite,))
        
        paquets = []
        for row in cursor.fetchall():
            paquet = dict(row)
            # Reconvertir le JSON
            if paquet['contenu_json']:
                try:
                    paquet['contenu'] = json.loads(paquet['contenu_json'])
                except:
                    paquet['contenu'] = {}
            paquets.append(paquet)
        
        return paquets
    
    def statistiques_paquets(self) -> Dict[str, Any]:
        """
        Retourne les statistiques des paquets SNMP
        
        Returns:
            Dict: Statistiques des paquets
        """
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
        cursor.execute('''
            SELECT DATE(timestamp_reception) as jour, COUNT(*) as count 
            FROM paquets_recus 
            WHERE timestamp_reception >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp_reception)
            ORDER BY jour DESC
        ''')
        stats['derniers_7_jours'] = dict(cursor.fetchall())
        
        return stats
    
    def rechercher_paquets(self, 
                          adresse_source: str = None,
                          adresse_dest: str = None,
                          version_snmp: str = None,
                          oid_racine: str = None,
                          date_debut: str = None,
                          date_fin: str = None) -> List[Dict]:
        """
        Recherche des paquets selon des critères
        
        Args:
            adresse_source (str, optional): Filtrer par adresse source
            adresse_dest (str, optional): Filtrer par adresse de destination
            version_snmp (str, optional): Filtrer par version SNMP  
            oid_racine (str, optional): Filtrer par OID
            date_debut (str, optional): Date de début (YYYY-MM-DD)
            date_fin (str, optional): Date de fin (YYYY-MM-DD)
            
        Returns:
            List[Dict]: Paquets correspondant aux critères
        """
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM paquets_recus WHERE 1=1"
        params = []
        
        if adresse_source:
            query += " AND adresse_source = ?"
            params.append(adresse_source)
        
        if adresse_dest:
            query+= " AND adresse_dest = ?"
            params.append(adresse_dest)
        
        if version_snmp:
            query += " AND version_snmp = ?"
            params.append(version_snmp)
        
        if oid_racine:
            query += " AND oid_racine LIKE ?"
            params.append(f"%{oid_racine}%")
        
        if date_debut:
            query += " AND DATE(timestamp_reception) >= ?"
            params.append(date_debut)
        
        if date_fin:
            query += " AND DATE(timestamp_reception) <= ?"
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
        """
        Génère une clé API unique utilisant SHA512 et des données aléatoires
        
        Returns:
            str: Clé API générée (affichée une fois à l'utilisateur, stockée sous forme de hash)
        """
        cle_api = secrets.token_urlsafe(48)
        return cle_api


    def ajouter_cle_api(self, description = "/") -> Optional[str]:
        """
        Ajoute une nouvelle clé API activée à la base de données
        
        Returns:
            str: Clé API générée, ou None en cas d'erreur
        """
        cursor = self.connection.cursor()
        
        try:
            cle = self.generer_cle_api()
            cle_hash = self.hash_sha512(cle)  # Hash avant stockage
            
            cursor.execute('''
                INSERT INTO cles_API (cle, activee, description)
                VALUES (?, 1, ?)
            ''', (cle_hash,description,))
            
            self.connection.commit()
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Création de la clé API - ID: {cursor.lastrowid}.\n")
            return cle
            
        except Exception as e:
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Erreur lors de la création d'une clé API - {e}.\n")
            return None

    def lister_cles_api(self, actives_seulement: bool = False) -> List[Dict]:
        """
        Liste les clés API avec leurs métadonnées
        
        Args:
            actives_seulement (bool): Si True, retourne uniquement les clés activées
            
        Returns:
            List[Dict]: Liste des clés API
        """
        cursor = self.connection.cursor()
        
        if actives_seulement:
            cursor.execute('''
                SELECT id, activee, description, date_creation 
                FROM cles_API 
                WHERE activee = 1
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
        """
        Vérifie si une clé API existe et est activée (compare les hashes)
        
        Args:
            cle (str): Clé API en clair fournie par l'utilisateur
            
        Returns:
            bool: True si la clé est valide et activée, False sinon
        """
        cursor = self.connection.cursor()
        cle_hash = self.hash_sha512(cle)  # Hash la clé fournie
        
        cursor.execute('''
            SELECT id FROM cles_API 
            WHERE cle = ? AND activee = 1
        ''', (cle_hash,))  # Compare les hashes
        
        return cursor.fetchone() is not None
    
    def desactiver_cle_api_par_id(self, id: int) -> bool:
        """
        Désactive une clé API (elle est conservée dans la base pour audit)
        
        Args:
            id (int): ID de la Clé API à désactiver
            
        Returns:
            bool: True si la clé a été désactivée
        """
        cursor = self.connection.cursor()
        
        cursor.execute('''
            UPDATE cles_API 
            SET activee = 0 
            WHERE ID = ?
        ''', (id,))
        
        self.connection.commit()
        
        if cursor.rowcount > 0:
            with open(self.log_file, 'a') as lf:
                lf.write("[" + datetime.now().strftime('%d-%m-%Y_%H:%M:%S') + f"] - Clé API ID {id} désactivée avec succès.\n")
            return True        
        return False


# Exemple d'utilisation et de test
def exemple_utilisation():
    """
    Fonction d'exemple montrant comment utiliser la classe SNMPDatabase
    """
    print("🚀 === EXEMPLE D'UTILISATION DE LA BASE DE DONNÉES SNMP ===")
    
    # Initialisation
    db = SNMPDatabase("exemple_snmp.db")
    
    print("\n📝 === GESTION DES UTILISATEURS ===")
    
    # Ajout d'utilisateurs de test
    db.ajouter_utilisateur("admin", "motdepasse123")
    db.ajouter_utilisateur("moniteur", "snmp2024!")
    
    # Vérification des identifiants
    print(f"✅ Connexion admin: {db.verifier_utilisateur('admin', 'motdepasse123')}")
    print(f"❌ Connexion invalide: {db.verifier_utilisateur('admin', 'mauvaismdp')}")
    
    # Liste des utilisateurs
    utilisateurs = db.lister_utilisateurs()
    print(f"👥 Nombre d'utilisateurs: {len(utilisateurs)}")
    
    print("\n📦 === GESTION DES PAQUETS SNMP ===")
    
    # Ajout de paquets SNMP de test
    
    # Paquet SNMP v2c
# ... dans exemple_utilisation ...

    # Paquet SNMP v2c (Exemple corrigé)
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
        contenu=contenu_v2c,        # On passe le contenu
        request_id=12345,           # OBLIGATOIRE
        error_index=0,              # OBLIGATOIRE
        communaute="public",
        oid_racine="1.3.6.1.2.1.1.1.0", # Attention: oid_racine vs oid
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
        error_status=contenu_v3["error_status"],
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
    print(f"📈 Statistiques: {json.dumps(stats, indent=2, ensure_ascii=False)}")
    
    print("\n🔍 === RECHERCHE DE PAQUETS ===")
    paquets_v3 = db.rechercher_paquets(version_snmp="v3")
    print(f"🔒 Paquets SNMP v3 trouvés: {len(paquets_v3)}")

    print("\n❤️ === CLÉS API ===")
    cles_apis = db.lister_cles_api()
    print(f"❤️ Clés APIS : {cles_apis}")
    
    # Liste des paquets récents
    paquets_recents = db.lister_paquets_snmp(limite=5)
    print(f"⏰ Paquets récents: {len(paquets_recents)}")
    
    # Fermeture de la base de données
    db.close()
    
    print("\n✅ === EXEMPLE TERMINÉ AVEC SUCCÈS ===")


if __name__ == "__main__":
    exemple_utilisation()