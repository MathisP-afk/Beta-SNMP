#!/usr/bin/env python3
"""
Script d'initialisation de la base de donnees PostgreSQL pour le conteneur Docker.
Attend que PostgreSQL soit pret, puis verifie et cree un utilisateur
par defaut + une cle API si necessaire.
"""

import os
import time
import secrets
import string
import psycopg2
from snmp_database_postgre import SNMPDatabase


def generer_mot_de_passe(longueur=16):
    """Genere un mot de passe respectant les regles de complexite de l'API."""
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%&*-_"
    password = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    alphabet = lower + upper + digits + special
    password += [secrets.choice(alphabet) for _ in range(longueur - 4)]
    result = list(password)
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def attendre_postgres(max_tentatives=30, intervalle=2):
    """Attend que PostgreSQL soit pret avant de continuer."""
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = int(os.environ.get("POSTGRES_PORT", "5432"))
    user = os.environ.get("POSTGRES_USER", "SylvAdminBDD")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    database = os.environ.get("POSTGRES_DB", "snmpdatabase")

    print(f"  Attente de PostgreSQL ({host}:{port})...")
    for i in range(max_tentatives):
        try:
            conn = psycopg2.connect(
                host=host, port=port, dbname=database,
                user=user, password=password,
                connect_timeout=3
            )
            conn.close()
            print(f"  PostgreSQL pret (tentative {i + 1}/{max_tentatives})")
            return True
        except psycopg2.OperationalError:
            time.sleep(intervalle)

    print(f"  ERREUR : PostgreSQL non disponible apres {max_tentatives} tentatives")
    return False


def main():
    print("=" * 60)
    print("  INITIALISATION DE LA BASE DE DONNEES POSTGRESQL")
    print("=" * 60)

    if not attendre_postgres():
        exit(1)

    print()
    db = SNMPDatabase()
    print(f"  Connecte a : {db.host}:{db.port}/{db.database}")
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
