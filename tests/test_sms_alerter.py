import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from dotenv import load_dotenv

# --- Configuration des chemins d'import ---
current_dir = os.path.dirname(os.path.abspath(__file__))
api_path = os.path.join(current_dir, '..', 'Centrale_SQLIte')
sys.path.append(api_path)

# Charger le .env.test depuis le répertoire tests/
dotenv_path = os.path.join(current_dir, '.env.test')
load_dotenv(dotenv_path)

from sms_alerter import envoyer_sms_alerte, charger_config_twilio


class TestSMSAlerter(unittest.TestCase):
    """Tests unitaires pour le module d'alerte SMS Twilio"""

    def setUp(self):
        """Configuration commune : variables d'environnement Twilio simulées"""
        self.env_twilio = {
            "TWILIO_ACCOUNT_SID": "ACtest123456789",
            "TWILIO_AUTH_TOKEN": "auth_token_test",
            "TWILIO_FROM_NUMBER": "+15551234567",
            "TWILIO_TO_NUMBER": "+33612345678",
        }
        self.contenu_critique = {
            "varbinds": [],
            "alerte_securite": {
                "niveau": "CRITIQUE",
                "message": "Community string par défaut détectée"
            }
        }
        self.contenu_elevee = {
            "varbinds": [],
            "alerte_securite": {
                "niveau": "ELEVEE",
                "message": "Requête SET suspecte"
            }
        }
        self.contenu_normal = {
            "varbinds": [],
            "alerte_securite": {
                "niveau": "NORMAL",
                "message": "Aucune anomalie"
            }
        }
        self.contenu_suspect = {
            "varbinds": [],
            "alerte_securite": {
                "niveau": "SUSPECT",
                "message": "Activité inhabituelle"
            }
        }
        self.source_ip = "192.168.1.100"

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_envoyer_sms_critique_appelle_twilio(self, mock_client_cls):
        """Vérifie qu'un SMS est envoyé quand le niveau est CRITIQUE"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        envoyer_sms_alerte(self.contenu_critique, self.source_ip)

        mock_client.messages.create.assert_called_once()
        call_kwargs = mock_client.messages.create.call_args[1]
        self.assertEqual(call_kwargs["from_"], "+15551234567")
        self.assertEqual(call_kwargs["to"], "+33612345678")

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_envoyer_sms_elevee_appelle_twilio(self, mock_client_cls):
        """Vérifie qu'un SMS est envoyé quand le niveau est ELEVEE"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        envoyer_sms_alerte(self.contenu_elevee, self.source_ip)

        mock_client.messages.create.assert_called_once()

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_pas_de_sms_si_niveau_normal(self, mock_client_cls):
        """Vérifie qu'aucun SMS n'est envoyé pour le niveau NORMAL"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        envoyer_sms_alerte(self.contenu_normal, self.source_ip)

        mock_client.messages.create.assert_not_called()

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_pas_de_sms_si_niveau_suspect(self, mock_client_cls):
        """Vérifie qu'aucun SMS n'est envoyé pour le niveau SUSPECT"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        envoyer_sms_alerte(self.contenu_suspect, self.source_ip)

        mock_client.messages.create.assert_not_called()

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_pas_de_sms_sans_alerte_securite(self, mock_client_cls):
        """Vérifie qu'aucun SMS n'est envoyé si contenu ne contient pas alerte_securite"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        contenu_sans_alerte = {"varbinds": []}
        envoyer_sms_alerte(contenu_sans_alerte, self.source_ip)

        mock_client.messages.create.assert_not_called()

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_sms_contient_infos_pertinentes(self, mock_client_cls):
        """Vérifie que le corps du SMS contient l'IP source, le niveau et le message"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        envoyer_sms_alerte(self.contenu_critique, self.source_ip)

        call_kwargs = mock_client.messages.create.call_args[1]
        body = call_kwargs["body"]
        self.assertIn("192.168.1.100", body)
        self.assertIn("CRITIQUE", body)
        self.assertIn("Community string par défaut détectée", body)

    @patch.dict(os.environ, {
        "TWILIO_ACCOUNT_SID": "ACtest123456789",
        "TWILIO_AUTH_TOKEN": "auth_token_test",
        "TWILIO_FROM_NUMBER": "+15551234567",
        "TWILIO_TO_NUMBER": "+33612345678",
    })
    @patch("sms_alerter.Client")
    def test_erreur_twilio_ne_crash_pas(self, mock_client_cls):
        """Vérifie que si Twilio lève une exception, la fonction ne propage pas l'erreur"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.side_effect = Exception("Erreur réseau Twilio")

        # Ne doit pas lever d'exception
        try:
            envoyer_sms_alerte(self.contenu_critique, self.source_ip)
        except Exception:
            self.fail("envoyer_sms_alerte ne doit pas propager les exceptions Twilio")

    @patch.dict(os.environ, {}, clear=True)
    @patch("sms_alerter.Client")
    def test_sms_non_envoye_si_config_manquante(self, mock_client_cls):
        """Vérifie que si les variables d'env Twilio sont absentes, pas de crash"""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        # Ne doit pas lever d'exception
        try:
            envoyer_sms_alerte(self.contenu_critique, self.source_ip)
        except Exception:
            self.fail("envoyer_sms_alerte ne doit pas crasher si la config Twilio est absente")

        mock_client.messages.create.assert_not_called()


def _config_twilio_presente():
    """Vérifie que les 4 variables Twilio sont définies dans l'environnement"""
    return all(os.environ.get(v) for v in [
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN",
        "TWILIO_FROM_NUMBER", "TWILIO_TO_NUMBER"
    ])


@unittest.skipUnless(_config_twilio_presente(),
                     "Variables Twilio absentes du .env — test d'intégration ignoré")
class TestSMSAlerterIntegration(unittest.TestCase):
    """Tests d'intégration avec de vrais credentials Twilio (chargés depuis .env)"""

    def test_envoi_reel_sms_critique(self):
        """Envoie un vrai SMS de test via Twilio pour valider les credentials"""
        contenu = {
            "varbinds": [],
            "alerte_securite": {
                "niveau": "CRITIQUE",
                "message": "[TEST] Validation credentials Twilio"
            }
        }
        # Ne doit pas lever d'exception avec de vrais credentials
        try:
            envoyer_sms_alerte(contenu, "127.0.0.1")
        except Exception as e:
            self.fail(f"Envoi SMS réel a échoué : {e}")

    def test_charger_config_twilio_depuis_env(self):
        """Vérifie que charger_config_twilio() retourne un dict valide depuis le .env"""
        config = charger_config_twilio()
        self.assertIsNotNone(config, "charger_config_twilio() ne doit pas retourner None avec un .env valide")
        self.assertTrue(config["account_sid"].startswith("AC"),
                        "Le SID Twilio doit commencer par 'AC'")
        self.assertTrue(config["from_number"].startswith("+"),
                        "Le numéro from doit commencer par '+'")
        self.assertTrue(config["to_number"].startswith("+"),
                        "Le numéro to doit commencer par '+'")


if __name__ == '__main__':
    unittest.main()
