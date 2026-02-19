"""
Tests unitaires pour Central_Postgre (BDD mockée + API)
psycopg2 est mocké car il faut un serveur PostgreSQL réel.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
import json
import tempfile
import hashlib

current_dir = os.path.dirname(os.path.abspath(__file__))
postgre_path = os.path.join(current_dir, '..', 'Central_Postgre')
sys.path.insert(0, postgre_path)

LOG = os.path.join(tempfile.gettempdir(), "test_postgre.log")


# ============================================================================
# TESTS BASE DE DONNÉES (psycopg2 mocké)
# ============================================================================

class TestPostgreHash(unittest.TestCase):
    """Test du hachage SHA-512 (pas besoin de BDD)"""

    def test_hash_longueur(self):
        h = hashlib.sha512("test".encode('utf-8')).hexdigest()
        self.assertEqual(len(h), 128)

    def test_hash_deterministe(self):
        h1 = hashlib.sha512("abc".encode('utf-8')).hexdigest()
        h2 = hashlib.sha512("abc".encode('utf-8')).hexdigest()
        self.assertEqual(h1, h2)

    def test_hash_different(self):
        h1 = hashlib.sha512("a".encode('utf-8')).hexdigest()
        h2 = hashlib.sha512("b".encode('utf-8')).hexdigest()
        self.assertNotEqual(h1, h2)


class TestPostgreDatabase(unittest.TestCase):
    """Tests de la couche BDD PostgreSQL avec mock psycopg2"""

    @patch('snmp_database_postgre.psycopg2')
    def setUp(self, mock_psycopg2):
        self.mock_conn = MagicMock()
        self.mock_cursor = MagicMock()
        self.mock_conn.cursor.return_value = self.mock_cursor
        mock_psycopg2.connect.return_value = self.mock_conn
        mock_psycopg2.IntegrityError = Exception

        from snmp_database_postgre import SNMPDatabase
        self.SNMPDatabase = SNMPDatabase
        self.db = SNMPDatabase(
            host="localhost", port=5432, database="testdb",
            user="test", password="test", log_file=LOG
        )

    def test_connexion_appelee(self):
        """Vérifie que psycopg2.connect est appelé"""
        self.assertIsNotNone(self.db.connection)

    def test_initialize_database_cree_tables(self):
        """Vérifie que 3 CREATE TABLE sont exécutés"""
        # initialize_database est appelé dans __init__
        calls = [str(c) for c in self.mock_cursor.execute.call_args_list]
        create_calls = [c for c in calls if "CREATE TABLE" in c]
        self.assertEqual(len(create_calls), 3)

    def test_hash_sha512(self):
        h = self.db.hash_sha512("test")
        self.assertEqual(len(h), 128)

    def test_ajouter_utilisateur_succes(self):
        self.mock_cursor.fetchone.return_value = [1]
        result = self.db.ajouter_utilisateur("admin", "mdp123")
        self.assertTrue(result)
        self.mock_conn.commit.assert_called()

    def test_ajouter_utilisateur_doublon(self):
        from snmp_database_postgre import psycopg2
        self.mock_cursor.execute.side_effect = psycopg2.IntegrityError("duplicate")
        result = self.db.ajouter_utilisateur("admin", "mdp123")
        self.assertFalse(result)

    def test_verifier_utilisateur_ok(self):
        self.mock_cursor.fetchone.return_value = [1]
        result = self.db.verifier_utilisateur("admin", "mdp123")
        self.assertTrue(result)

    def test_verifier_utilisateur_mauvais_mdp(self):
        self.mock_cursor.fetchone.return_value = None
        result = self.db.verifier_utilisateur("admin", "wrong")
        self.assertFalse(result)

    def test_lister_utilisateurs(self):
        mock_dict_cursor = MagicMock()
        mock_dict_cursor.fetchall.return_value = [
            {"id": 1, "nom_utilisateur": "admin", "actif": True}
        ]
        self.mock_conn.cursor.return_value = mock_dict_cursor
        users = self.db.lister_utilisateurs()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["nom_utilisateur"], "admin")

    def test_ajouter_paquet_snmp(self):
        self.mock_cursor.fetchone.return_value = [42]
        result = self.db.ajouter_paquet_snmp(
            version_snmp="v2c", adresse_source="10.0.0.1", port_source=161,
            adresse_dest="10.0.0.2", port_dest=162,
            contenu={"varbinds": []}, request_id=1, type_pdu="GET"
        )
        self.assertTrue(result)

    def test_lister_paquets_snmp(self):
        mock_dict_cursor = MagicMock()
        mock_dict_cursor.fetchall.return_value = [
            {"id": 1, "version_snmp": "v2c", "adresse_source": "10.0.0.1",
             "contenu_json": '{"varbinds": []}'}
        ]
        self.mock_conn.cursor.return_value = mock_dict_cursor
        paquets = self.db.lister_paquets_snmp(limite=10)
        self.assertEqual(len(paquets), 1)
        self.assertIn("contenu", paquets[0])

    def test_lister_paquets_avec_filtre(self):
        mock_dict_cursor = MagicMock()
        mock_dict_cursor.fetchall.return_value = []
        self.mock_conn.cursor.return_value = mock_dict_cursor
        paquets = self.db.lister_paquets_snmp(version_snmp="v3")
        self.assertEqual(len(paquets), 0)

    def test_statistiques_paquets(self):
        self.mock_cursor.fetchone.return_value = [5]
        self.mock_cursor.fetchall.return_value = [("v2c", 3), ("v3", 2)]
        stats = self.db.statistiques_paquets()
        self.assertEqual(stats["total_paquets"], 5)

    def test_rechercher_paquets(self):
        mock_dict_cursor = MagicMock()
        mock_dict_cursor.fetchall.return_value = [
            {"id": 1, "adresse_source": "10.0.0.1", "contenu_json": '{"varbinds": []}'}
        ]
        self.mock_conn.cursor.return_value = mock_dict_cursor
        results = self.db.rechercher_paquets(adresse_source="10.0.0.1")
        self.assertEqual(len(results), 1)

    def test_generer_cle_api(self):
        cle = self.db.generer_cle_api()
        self.assertIsInstance(cle, str)
        self.assertGreater(len(cle), 0)

    def test_generer_cle_unique(self):
        self.assertNotEqual(self.db.generer_cle_api(), self.db.generer_cle_api())

    def test_ajouter_cle_api(self):
        self.mock_cursor.fetchone.return_value = [1]
        cle = self.db.ajouter_cle_api("test")
        self.assertIsNotNone(cle)

    def test_valider_cle_api_ok(self):
        self.mock_cursor.fetchone.return_value = [1]
        self.assertTrue(self.db.valider_cle_api("ma_cle"))

    def test_valider_cle_api_ko(self):
        self.mock_cursor.fetchone.return_value = None
        self.assertFalse(self.db.valider_cle_api("mauvaise"))

    def test_desactiver_cle_api(self):
        self.mock_cursor.rowcount = 1
        self.assertTrue(self.db.desactiver_cle_api_par_id(1))

    def test_desactiver_cle_inexistante(self):
        self.mock_cursor.rowcount = 0
        self.assertFalse(self.db.desactiver_cle_api_par_id(99999))


# ============================================================================
# TESTS API FastAPI (Central_Postgre)
# ============================================================================

class TestPostgreAPI(unittest.TestCase):
    """Tests de l'API avec la BDD mockée"""

    @classmethod
    def setUpClass(cls):
        # Mock complet de la BDD pour l'API
        cls.mock_db = MagicMock()
        cls.mock_db.valider_cle_api.return_value = True

        # Patcher le module API avant import
        with patch('snmp_database_postgre.psycopg2'):
            import snmp_api_improved_postgre as api_mod
            api_mod.db = cls.mock_db
            cls.api_mod = api_mod

        try:
            from fastapi.testclient import TestClient
        except ImportError:
            raise unittest.SkipTest("httpx requis pour TestClient")

        cls.client = TestClient(api_mod.app)
        cls.headers = {"Authorization": "Bearer test_key_valid"}

    def setUp(self):
        # Reset les mocks entre chaque test
        self.mock_db.reset_mock()
        self.mock_db.valider_cle_api.return_value = True

    def test_health(self):
        self.mock_db.lister_utilisateurs.return_value = []
        self.mock_db.lister_cles_api.return_value = []
        self.mock_db.statistiques_paquets.return_value = {"total_paquets": 0}
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)

    def test_sans_auth_refuse(self):
        self.mock_db.valider_cle_api.return_value = False
        r = self.client.get("/users/list")
        self.assertIn(r.status_code, [401, 403])

    def test_mauvaise_cle_401(self):
        self.mock_db.valider_cle_api.return_value = False
        r = self.client.get("/users/list", headers={"Authorization": "Bearer bad"})
        self.assertEqual(r.status_code, 401)

    def test_register_user(self):
        self.mock_db.ajouter_utilisateur.return_value = True
        r = self.client.post("/users/register",
            json={"username": "tuser", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "success")

    def test_register_doublon_409(self):
        self.mock_db.ajouter_utilisateur.return_value = False
        r = self.client.post("/users/register",
            json={"username": "dup", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r.status_code, 409)

    def test_mdp_faible_422(self):
        r = self.client.post("/users/register",
            json={"username": "weak", "password": "faible"},
            headers=self.headers)
        self.assertEqual(r.status_code, 422)

    def test_login_ok(self):
        self.mock_db.verifier_utilisateur.return_value = True
        r = self.client.post("/auth/login",
            json={"username": "usr", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r.status_code, 200)

    def test_login_echec_401(self):
        self.mock_db.verifier_utilisateur.return_value = False
        r = self.client.post("/auth/login",
            json={"username": "usr", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r.status_code, 401)

    def test_list_users(self):
        self.mock_db.lister_utilisateurs.return_value = [{"nom_utilisateur": "a"}]
        r = self.client.get("/users/list", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("utilisateurs", r.json())

    def test_create_api_key(self):
        self.mock_db.ajouter_cle_api.return_value = "new_key_123"
        r = self.client.post("/api-keys/create",
            json={"description": "new"}, headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("api_key", r.json())

    def test_list_api_keys(self):
        self.mock_db.lister_cles_api.return_value = []
        r = self.client.get("/api-keys/list", headers=self.headers)
        self.assertEqual(r.status_code, 200)

    def test_revoke_ok(self):
        self.mock_db.desactiver_cle_api_par_id.return_value = True
        r = self.client.delete("/api-keys/revoke/1", headers=self.headers)
        self.assertEqual(r.status_code, 200)

    def test_revoke_404(self):
        self.mock_db.desactiver_cle_api_par_id.return_value = False
        r = self.client.delete("/api-keys/revoke/99999", headers=self.headers)
        self.assertEqual(r.status_code, 404)

    def test_add_v2c(self):
        self.mock_db.ajouter_paquet_snmp.return_value = True
        r = self.client.post("/snmp/v2c/add", json={
            "source_ip": "10.0.0.1", "source_port": 161,
            "dest_ip": "10.0.0.2", "dest_port": 162,
            "community": "public", "oid_racine": "1.3.6.1",
            "type_pdu": "GET", "request_id": 1
        }, headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["version"], "v2c")

    def test_add_v3(self):
        self.mock_db.ajouter_paquet_snmp.return_value = True
        r = self.client.post("/snmp/v3/add", json={
            "source_ip": "10.0.0.3", "source_port": 161,
            "dest_ip": "10.0.0.4", "dest_port": 162,
            "oid_racine": "1.3.6.1", "type_pdu": "GET",
            "contexte": "ctx", "niveau_securite": "authPriv",
            "utilisateur": "u", "request_id": 2
        }, headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["version"], "v3")

    def test_port_invalide_422(self):
        r = self.client.post("/snmp/v2c/add", json={
            "source_ip": "10.0.0.1", "source_port": 99999,
            "dest_ip": "10.0.0.2", "dest_port": 162,
            "oid_racine": "1.3.6.1", "type_pdu": "GET", "request_id": 1
        }, headers=self.headers)
        self.assertEqual(r.status_code, 422)

    def test_list_snmp(self):
        self.mock_db.lister_paquets_snmp.return_value = []
        r = self.client.get("/snmp/list", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("trames", r.json())

    def test_search_snmp(self):
        self.mock_db.rechercher_paquets.return_value = []
        r = self.client.get("/snmp/search?adresse_source=10.0.0.1", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("filtres", r.json())

    def test_statistics(self):
        self.mock_db.statistiques_paquets.return_value = {"total_paquets": 0}
        r = self.client.get("/snmp/statistics", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("statistiques", r.json())


if __name__ == '__main__':
    unittest.main()
