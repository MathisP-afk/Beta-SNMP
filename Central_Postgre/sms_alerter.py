# Module d'alerte SMS via Twilio pour trames SNMP critiques

import os
import logging
from dotenv import load_dotenv
from twilio.rest import Client

load_dotenv()

logger = logging.getLogger("sms_alerter")

NIVEAUX_ALERTES_SMS = {"CRITIQUE", "ELEVEE"}


def charger_config_twilio():
    """
    Charge la configuration Twilio depuis les variables d'environnement.
    Retourne un dict avec les credentials ou None si la config est incomplète.
    """
    config = {
        "account_sid": os.environ.get("TWILIO_ACCOUNT_SID"),
        "auth_token": os.environ.get("TWILIO_AUTH_TOKEN"),
        "from_number": os.environ.get("TWILIO_FROM_NUMBER"),
        "to_number": os.environ.get("TWILIO_TO_NUMBER"),
    }
    if all(config.values()):
        return config
    logger.warning("Configuration Twilio incomplète — SMS désactivés")
    return None


def envoyer_sms_alerte(contenu: dict, source_ip: str):
    """
    Envoie un SMS d'alerte si la trame contient une alerte de sécurité
    de niveau CRITIQUE ou ELEVEE.

    Ne propage jamais d'exception pour ne pas impacter l'API.
    """
    try:
        alerte = contenu.get("alerte_securite")
        if not alerte:
            return

        niveau = alerte.get("niveau", "")
        if niveau not in NIVEAUX_ALERTES_SMS:
            return

        config = charger_config_twilio()
        if not config:
            return

        message_alerte = alerte.get("message", "Aucun détail")
        body = (
            f"[SNMP Alerte {niveau}] "
            f"Source: {source_ip} — "
            f"{message_alerte}"
        )

        client = Client(config["account_sid"], config["auth_token"])
        client.messages.create(
            body=body,
            from_=config["from_number"],
            to=config["to_number"],
        )
        logger.info("SMS alerte envoyé pour %s (niveau %s)", source_ip, niveau)

    except Exception as e:
        logger.error("Echec envoi SMS alerte : %s", e)
