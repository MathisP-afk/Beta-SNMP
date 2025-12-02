import sys
import os
import unittest
import sqlite3

# --- Configuration des chemins d'import ---
# On ajoute le dossier "API + BDD" au path pour que Python trouve snmp_database.py
current_dir = os.path.dirname(os.path.abspath(__file__))
api_path = os.path.join(current_dir, '../API + BDD')
sys.path.append(api_path)

try:
    from snmp_database import SNMPDatabase
except ImportError:
    # Fallback si le dossier s'appelle différemment sur le repo
    sys.path.append(os.path.join(current_dir, '../API_BDD'))
    from snmp_database import SNMPDatabase

class TestSNMPDatabase(unittest.TestCase):
    
    def setUp(self):
        """S'exécute avant chaque test : on crée une BDD temporaire en mémoire"""
        self.db = SNMPDatabase(":memory:", log_file="test_log.txt")
        # On force la création des tables car :memory: est vide
        self.db.initialize_database()

    def test_hash_sha512(self):
        """Test 1: Vérifier que le hachage fonctionne"""
        texte = "monMotDePasse"
        hash_result = self.db.hash_sha512(texte)
        # Un hash SHA-512 fait toujours 128 caractères hexadécimaux
        self.assertEqual(len(hash_result), 128)
        self.assertNotEqual(texte, hash_result)

    def test_ajouter_et_verifier_utilisateur(self):
        """Test 2: Créer un utilisateur et vérifier sa connexion"""
        user = "test_admin"
        pwd = "password123"
        
        # Ajout
        ajout_ok = self.db.ajouter_utilisateur(user, pwd)
        self.assertTrue(ajout_ok, "L'utilisateur aurait dû être ajouté")
        
        # Vérification succès
        login_ok = self.db.verifier_utilisateur(user, pwd)
        self.assertTrue(login_ok, "Le login devrait réussir avec le bon mot de passe")
        
        # Vérification échec
        login_fail = self.db.verifier_utilisateur(user, "mauvais_mdp")
        self.assertFalse(login_fail, "Le login devrait échouer avec un mauvais mot de passe")

    def tearDown(self):
        """Nettoyage après les tests"""
        self.db.close()

if __name__ == '__main__':
    unittest.main()