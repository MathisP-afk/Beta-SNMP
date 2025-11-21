# Fichier: generer_cle.py
from snmp_database import SNMPDatabase
import os

# On s'assure d'être dans le bon dossier pour la BDD
if os.path.exists("snmp_api.db"):
    print("Base de données trouvée.")
else:
    print("⚠️ Attention : snmp_api.db non trouvée ici, une nouvelle sera créée.")

try:
    # Connexion à la BDD
    db = SNMPDatabase("snmp_api.db")
    
    # Génération de la clé
    nouvelle_cle = db.ajouter_cle_api(description="Clé manuelle admin")
    
    print("\n" + "█"*50)
    print("█" + " "*48 + "█")
    print(f"█   VOTRE CLÉ API EST :   {nouvelle_cle}")
    print("█" + " "*48 + "█")
    print("█"*50 + "\n")
    
except Exception as e:
    print(f"Erreur : {e}")
    print("Vérifiez que snmp_database.py est bien dans le même dossier.")