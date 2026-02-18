#!/usr/bin/env python3
"""
Script d'initialisation de la base de donnees pour le conteneur Docker.
Verifie et cree un utilisateur par defaut + une cle API si necessaire.
Affiche les credentials en sortie standard (visible dans docker logs).
"""

import os
import secrets
import string
from snmp_database import SNMPDatabase


def generer_mot_de_passe(longueur=16):
    """Genere un mot de passe respectant les regles de complexite de l'API."""
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%&*-_"
    # Garantir au moins un de chaque type
    password = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    # Completer avec des caracteres aleatoires
    alphabet = lower + upper + digits + special
    password += [secrets.choice(alphabet) for _ in range(longueur - 4)]
    # Melanger
    result = list(password)
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def main():
    print("=" * 60)
    print("  INITIALISATION DE LA BASE DE DONNEES")
    print("=" * 60)

    db = SNMPDatabase()
    print(f"  Base de donnees : {db.db_path}")
    print()

    # --- Verification / Creation utilisateur ---
    utilisateurs = db.lister_utilisateurs()
    if utilisateurs:
        print(f"  Utilisateurs existants : {len(utilisateurs)}")
        for u in utilisateurs:
            print(f"    - {u['nom_utilisateur']}")
    else:
        username = "admin"
        password = generer_mot_de_passe()
        db.ajouter_utilisateur(username, password)
        print("  Utilisateur cree :")
        print(f"    Nom d'utilisateur : {username}")
        print(f"    Mot de passe      : {password}")
        print()
        print("  ** Conservez ces identifiants, ils ne seront plus affiches ! **")

    print()

    # --- Verification / Creation cle API ---
    cles = db.lister_cles_api(actives_seulement=True)
    if cles:
        print(f"  Cles API actives : {len(cles)}")
    else:
        cle = db.ajouter_cle_api(description="Cle initiale generee au demarrage du conteneur")
        if cle:
            print("  Cle API creee :")
            print(f"    {cle}")
            print()
            print("  ** Conservez cette cle, elle ne sera plus affichee ! **")
        else:
            print("  ERREUR : Impossible de creer la cle API")

    print()
    print("=" * 60)
    print("  INITIALISATION TERMINEE")
    print("=" * 60)
    print()

    db.close()


if __name__ == "__main__":
    main()
