"""
Tests unitaires pour Centrale_SQLIte (BDD + API)
"""

import sys
import os
import unittest
import tempfile

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, '..', 'Centrale_SQLIte'))

from snmp_database import SNMPDatabase

LOG = os.path.join(tempfile.gettempdir(), "test_sqlite.log")


# ============================================================================
# TESTS BASE DE DONNÉES
# ============================================================================

class TestHash(unittest.TestCase):

    def setUp(self):
        self.db = SNMPDatabase(":memory:", log_file=LOG)

    def tearDown(self):
        self.db.close()

    def test_hash_longueur(self):
        self.assertEqual(len(self.db.hash_sha512("test")), 128)

    def test_hash_deterministe(self):
        self.assertEqual(self.db.hash_sha512("abc"), self.db.hash_sha512("abc"))

    def test_hash_different(self):
        self.assertNotEqual(self.db.hash_sha512("a"), self.db.hash_sha512("b"))


class TestUtilisateurs(unittest.TestCase):

    def setUp(self):
        self.db = SNMPDatabase(":memory:", log_file=LOG)

    def tearDown(self):
        self.db.close()

    def test_ajout_ok(self):
        self.assertTrue(self.db.ajouter_utilisateur("admin", "mdp123"))

    def test_ajout_doublon(self):
        self.db.ajouter_utilisateur("admin", "mdp123")
        self.assertFalse(self.db.ajouter_utilisateur("admin", "autre"))

    def test_login_ok(self):
        self.db.ajouter_utilisateur("user", "pass")
        self.assertTrue(self.db.verifier_utilisateur("user", "pass"))

    def test_login_mauvais_mdp(self):
        self.db.ajouter_utilisateur("user", "pass")
        self.assertFalse(self.db.verifier_utilisateur("user", "wrong"))

    def test_login_inexistant(self):
        self.assertFalse(self.db.verifier_utilisateur("ghost", "pass"))

    def test_lister(self):
        self.db.ajouter_utilisateur("a", "1")
        self.db.ajouter_utilisateur("b", "2")
        self.assertEqual(len(self.db.lister_utilisateurs()), 2)

    def test_derniere_connexion(self):
        self.db.ajouter_utilisateur("u", "p")
        self.assertIsNone(self.db.lister_utilisateurs()[0]["derniere_connexion"])
        self.db.verifier_utilisateur("u", "p")
        self.assertIsNotNone(self.db.lister_utilisateurs()[0]["derniere_connexion"])


class TestPaquets(unittest.TestCase):

    def setUp(self):
        self.db = SNMPDatabase(":memory:", log_file=LOG)
        self.contenu = {"varbinds": [{"oid": "1.3.6.1.2.1.1.1.0", "value": "Linux"}]}

    def tearDown(self):
        self.db.close()

    def _ajout_v2c(self, src="10.0.0.1", rid=1):
        return self.db.ajouter_paquet_snmp(
            version_snmp="v2c", adresse_source=src, port_source=161,
            adresse_dest="10.0.0.2", port_dest=162,
            contenu=self.contenu, request_id=rid, type_pdu="GET",
            communaute="public", oid_racine="1.3.6.1.2.1.1.1.0"
        )

    def test_ajout_v2c(self):
        self.assertTrue(self._ajout_v2c())

    def test_ajout_v3(self):
        self.assertTrue(self.db.ajouter_paquet_snmp(
            version_snmp="v3", adresse_source="10.0.0.3", port_source=161,
            adresse_dest="10.0.0.4", port_dest=162,
            contenu=self.contenu, request_id=2, type_pdu="GET",
            utilisateur_v3="u", niveau_securite="authPriv", contexte_v3="ctx"
        ))

    def test_lister(self):
        self._ajout_v2c()
        paquets = self.db.lister_paquets_snmp(limite=10)
        self.assertEqual(len(paquets), 1)
        self.assertEqual(paquets[0]["adresse_source"], "10.0.0.1")

    def test_lister_filtre_version(self):
        self._ajout_v2c()
        self.db.ajouter_paquet_snmp(
            version_snmp="v3", adresse_source="10.0.0.5", port_source=161,
            adresse_dest="10.0.0.6", port_dest=162,
            contenu=self.contenu, request_id=2, type_pdu="GET",
            utilisateur_v3="u", niveau_securite="noAuthNoPriv", contexte_v3="c"
        )
        self.assertEqual(len(self.db.lister_paquets_snmp(version_snmp="v2c")), 1)
        self.assertEqual(len(self.db.lister_paquets_snmp(version_snmp="v3")), 1)

    def test_lister_limite(self):
        for i in range(5):
            self._ajout_v2c(rid=i)
        self.assertEqual(len(self.db.lister_paquets_snmp(limite=3)), 3)

    def test_contenu_json_deserialise(self):
        self._ajout_v2c()
        p = self.db.lister_paquets_snmp()[0]
        self.assertIn("contenu", p)
        self.assertIsInstance(p["contenu"], dict)

    def test_recherche_par_source(self):
        self._ajout_v2c(src="192.168.1.100")
        self._ajout_v2c(src="192.168.1.200", rid=2)
        r = self.db.rechercher_paquets(adresse_source="192.168.1.100")
        self.assertEqual(len(r), 1)

    def test_recherche_par_oid(self):
        self._ajout_v2c()
        r = self.db.rechercher_paquets(oid_racine="1.3.6.1")
        self.assertEqual(len(r), 1)

    def test_statistiques_vide(self):
        s = self.db.statistiques_paquets()
        self.assertEqual(s["total_paquets"], 0)

    def test_statistiques(self):
        self._ajout_v2c()
        self._ajout_v2c(rid=2)
        s = self.db.statistiques_paquets()
        self.assertEqual(s["total_paquets"], 2)
        self.assertIn("v2c", s["par_version"])


class TestClesAPI(unittest.TestCase):

    def setUp(self):
        self.db = SNMPDatabase(":memory:", log_file=LOG)

    def tearDown(self):
        self.db.close()

    def test_generer_non_vide(self):
        self.assertGreater(len(self.db.generer_cle_api()), 0)

    def test_generer_unique(self):
        self.assertNotEqual(self.db.generer_cle_api(), self.db.generer_cle_api())

    def test_ajouter_et_valider(self):
        cle = self.db.ajouter_cle_api("test")
        self.assertIsNotNone(cle)
        self.assertTrue(self.db.valider_cle_api(cle))

    def test_valider_fausse_cle(self):
        self.assertFalse(self.db.valider_cle_api("cle_bidon"))

    def test_lister(self):
        self.db.ajouter_cle_api("c1")
        self.db.ajouter_cle_api("c2")
        self.assertEqual(len(self.db.lister_cles_api()), 2)

    def test_desactiver(self):
        cle = self.db.ajouter_cle_api("a desactiver")
        cle_id = self.db.lister_cles_api()[0]["id"]
        self.assertTrue(self.db.desactiver_cle_api_par_id(cle_id))
        self.assertFalse(self.db.valider_cle_api(cle))

    def test_desactiver_inexistante(self):
        self.assertFalse(self.db.desactiver_cle_api_par_id(99999))


# ============================================================================
# TESTS API FastAPI
# ============================================================================

class TestAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db = SNMPDatabase(":memory:", log_file=LOG)
        import snmp_api_improved as api_mod
        api_mod.db = cls.test_db
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            raise unittest.SkipTest("httpx requis pour TestClient")
        cls.client = TestClient(api_mod.app)
        cls.api_key = cls.test_db.ajouter_cle_api("test")
        cls.headers = {"Authorization": f"Bearer {cls.api_key}"}

    @classmethod
    def tearDownClass(cls):
        cls.test_db.close()

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)

    def test_sans_auth_refuse(self):
        self.assertIn(self.client.get("/users/list").status_code, [401, 403])

    def test_mauvaise_cle_401(self):
        r = self.client.get("/users/list", headers={"Authorization": "Bearer bad"})
        self.assertEqual(r.status_code, 401)

    def test_register_et_login(self):
        r = self.client.post("/users/register",
            json={"username": "tuser", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r.status_code, 200)
        r2 = self.client.post("/auth/login",
            json={"username": "tuser", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r2.status_code, 200)

    def test_register_doublon_409(self):
        self.client.post("/users/register",
            json={"username": "dup", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        r = self.client.post("/users/register",
            json={"username": "dup", "password": "TestP@ssw0rd!"},
            headers=self.headers)
        self.assertEqual(r.status_code, 409)

    def test_mdp_faible_422(self):
        r = self.client.post("/users/register",
            json={"username": "weak", "password": "faible"},
            headers=self.headers)
        self.assertEqual(r.status_code, 422)

    def test_list_users(self):
        r = self.client.get("/users/list", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("utilisateurs", r.json())

    def test_create_api_key(self):
        r = self.client.post("/api-keys/create",
            json={"description": "new"}, headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("api_key", r.json())

    def test_list_api_keys(self):
        r = self.client.get("/api-keys/list", headers=self.headers)
        self.assertEqual(r.status_code, 200)

    def test_revoke_inexistante_404(self):
        r = self.client.delete("/api-keys/revoke/99999", headers=self.headers)
        self.assertEqual(r.status_code, 404)

    def test_add_v2c(self):
        r = self.client.post("/snmp/v2c/add", json={
            "source_ip": "10.0.0.1", "source_port": 161,
            "dest_ip": "10.0.0.2", "dest_port": 162,
            "community": "public", "oid_racine": "1.3.6.1",
            "type_pdu": "GET", "request_id": 1
        }, headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["version"], "v2c")

    def test_add_v3(self):
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
        r = self.client.get("/snmp/list", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("trames", r.json())

    def test_search_snmp(self):
        r = self.client.get("/snmp/search?adresse_source=10.0.0.1", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("filtres", r.json())

    def test_statistics(self):
        r = self.client.get("/snmp/statistics", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("statistiques", r.json())


if __name__ == '__main__':
    unittest.main()
