# API SNMP AMÉLIORÉE - FastAPI avec gestion des clés API en BDD
# Adaptée pour la nouvelle version de snmp_database.py

from snmp_database_postgre import SNMPDatabase  # ← Remplace snmp_database
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field, field_validator
from typing import Annotated, Optional, List, Dict, Any
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import re
import json

# ============================================================================
# INITIALISATION DE L'API ET DE LA BASE DE DONNÉES
# ============================================================================

db = SNMPDatabase()
db.ajouter_cle_api(description="Clé initiale générée au démarrage de l'API")
app = FastAPI(
    title="API SNMP Monitoring",
    description="API pour gérer les trames SNMP, utilisateurs et clés API",
    version="2.0.0"  # Version incrémentée
)

# Activation de la sécurité avec Bearer Token
security = HTTPBearer()

# ============================================================================
# FONCTION DE VALIDATION DE CLÉ API
# ============================================================================

async def validate_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Valide la clé API fournie dans l'en-tête Authorization
    Utilise la base de données pour vérifier la validité de la clé
    
    Args:
        credentials: Les credentials HTTP Bearer fournis
        
    Returns:
        str: La clé API masquée pour l'affichage
        
    Raises:
        HTTPException: Si la clé est invalide ou inactive
    """
    if not db.valider_cle_api(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API invalide ou inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials[:10] + "..."

# ============================================================================
# MODÈLES PYDANTIC POUR LA VALIDATION DES DONNÉES
# ============================================================================

class PostUtilisateur(BaseModel):
    """Modèle pour l'ajout/authentification d'un utilisateur"""
    username: Annotated[str, Field(min_length=3, description="Nom d'utilisateur")]
    password: Annotated[str, Field(min_length=12, description="Mot de passe complexe")]
    
    @field_validator("password")
    def check_password_complexity(cls, v: str) -> str:
        """Valide la complexité du mot de passe"""
        if not re.search(r"[a-z]", v):
            raise ValueError("Minimum une lettre minuscule")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Minimum une lettre majuscule")
        if not re.search(r"\d", v):
            raise ValueError("Minimum un chiffre")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Minimum un caractère spécial")
        return v

class PostTrameSNMPv2c(BaseModel):
    """Modèle pour l'ajout d'une trame SNMP v2c"""
    source_ip: Annotated[str, Field(description="IP source")]
    source_port: Annotated[int, Field(ge=1, le=65535, description="Port source (1-65535)")]
    dest_ip: Annotated[str, Field(description="IP de destination")]
    dest_port: Annotated[int, Field(ge=1, le=65535, description="Port destination (1-65535)")]
    community: Annotated[str, Field(default="public", description="Community string")]
    oid_racine: Annotated[str, Field(description="OID racine (premier OID)")]
    type_pdu: Annotated[str, Field(description="Type de PDU (GET-REQUEST, SET-REQUEST, etc.)")]
    request_id: Annotated[int, Field(description="ID de la requête SNMP")]
    error_status: Annotated[str, Field(default="0", description="Status d'erreur (0=noError)")]
    error_index: Annotated[int, Field(default=0, description="Index de l'erreur")]
    contenu: Annotated[Optional[Dict[str, Any]], Field(default=None, description="Contenu du PDU (VarBinds)")]

class PostTrameSNMPv3(BaseModel):
    """Modèle pour l'ajout d'une trame SNMP v3"""
    source_ip: Annotated[str, Field(description="IP source")]
    source_port: Annotated[int, Field(ge=1, le=65535, description="Port source (1-65535)")]
    dest_ip: Annotated[str, Field(description="IP de destination")]
    dest_port: Annotated[int, Field(ge=1, le=65535, description="Port destination (1-65535)")]
    oid_racine: Annotated[str, Field(description="OID racine")]
    type_pdu: Annotated[str, Field(description="Type de PDU")]
    contexte: Annotated[str, Field(description="Contexte SNMP v3")]
    niveau_securite: Annotated[str, Field(description="Niveau: noAuthNoPriv, authNoPriv, authPriv")]
    utilisateur: Annotated[str, Field(description="Utilisateur SNMP v3")]
    request_id: Annotated[int, Field(description="ID de la requête SNMP")]
    error_status: Annotated[str, Field(default="0", description="Status d'erreur")]
    error_index: Annotated[int, Field(default=0, description="Index de l'erreur")]
    engine_id: Annotated[Optional[str], Field(default=None, description="Engine ID SNMP v3")]
    msg_id: Annotated[Optional[int], Field(default=None, description="Message ID")]
    contenu: Annotated[Optional[Dict[str, Any]], Field(default=None, description="Contenu du PDU")]

class PostClexAPI(BaseModel):
    """Modèle pour la création d'une clé API"""
    description: Annotated[str, Field(default="Clé API générée via l'API", description="Description de la clé")]

# ============================================================================
# ENDPOINTS - GESTION DES UTILISATEURS
# ============================================================================

@app.post("/auth/login",
    summary="Authentifier un utilisateur",
    description="Authentifie un utilisateur avec ses credentials",
    tags=["Authentification"],
    responses={200: {"description": "Authentification réussie"}, 401: {"description": "Credentials invalides"}}
)
def login_user(
    user_creds: PostUtilisateur,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Authentifie un utilisateur"""
    if db.verifier_utilisateur(user_creds.username, user_creds.password):
        return {
            "status": "success",
            "message": f"Authentification réussie. Bienvenue {user_creds.username}",
            "username": user_creds.username,
            "authorized_by": api_key
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect"
        )

@app.post("/users/register",
    summary="Créer un nouvel utilisateur",
    description="Crée un nouvel utilisateur dans la base de données",
    tags=["Gestion Utilisateurs"],
    responses={201: {"description": "Utilisateur créé"}, 409: {"description": "Utilisateur existe déjà"}}
)
def register_user(
    user_creds: PostUtilisateur,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Crée un nouvel utilisateur"""
    success = db.ajouter_utilisateur(user_creds.username, user_creds.password)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Utilisateur '{user_creds.username}' existe déjà"
        )
    
    return {
        "status": "success",
        "message": f"Utilisateur '{user_creds.username}' créé avec succès",
        "username": user_creds.username,
        "authorized_by": api_key
    }

@app.get("/users/list",
    summary="Lister les utilisateurs",
    description="Retourne la liste de tous les utilisateurs actifs",
    tags=["Gestion Utilisateurs"]
)
def list_users(api_key: str = Depends(validate_api_key)) -> Dict[str, Any]:
    """Liste tous les utilisateurs actifs"""
    utilisateurs = db.lister_utilisateurs()
    
    return {
        "status": "success",
        "count": len(utilisateurs),
        "utilisateurs": utilisateurs,
        "authorized_by": api_key
    }

# ============================================================================
# ENDPOINTS - GESTION DES CLÉS API
# ============================================================================

@app.post("/api-keys/create",
    summary="Générer une nouvelle clé API",
    description="Crée une nouvelle clé API active",
    tags=["Gestion Clés API"]
)
def create_api_key(
    cle_info: PostClexAPI,
    api_key: str = Depends(validate_api_key),
) -> Dict[str, Any]:
    """Génère une nouvelle clé API"""
    nouvelle_cle = db.ajouter_cle_api(description=cle_info.description)
    
    if not nouvelle_cle:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la création de la clé API"
        )
    
    return {
        "status": "success",
        "message": "Clé API créée avec succès. ⚠️ Conservez-la en sécurité, elle ne s'affichera plus!",
        "api_key": nouvelle_cle,
        "description": cle_info.description,
        "authorized_by": api_key
    }

@app.get("/api-keys/list",
    summary="Lister les clés API",
    description="Retourne la liste des clés API (sans les valeurs complètes)",
    tags=["Gestion Clés API"]
)
def list_api_keys(
    actives_seulement: bool = False,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Liste les clés API"""
    cles = db.lister_cles_api(actives_seulement=actives_seulement)
    
    return {
        "status": "success",
        "count": len(cles),
        "cles_api": cles,
        "authorized_by": api_key
    }

@app.delete("/api-keys/revoke/{cle_id}",
    summary="Révoquer une clé API par ID",
    description="Désactive une clé API en utilisant son ID",
    tags=["Gestion Clés API"]
)
def revoke_api_key(
    cle_id: int,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Désactive une clé API par son ID"""
    success = db.desactiver_cle_api_par_id(cle_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Clé API avec ID {cle_id} non trouvée"
        )
    
    return {
        "status": "success",
        "message": f"Clé API #{cle_id} révoquée avec succès",
        "authorized_by": api_key
    }

# ============================================================================
# ENDPOINTS - GESTION DES TRAMES SNMP v2c
# ============================================================================

@app.post("/snmp/v2c/add",
    summary="Ajouter une trame SNMP v2c",
    description="Enregistre une trame SNMP v2c dans la base de données",
    tags=["Trames SNMP v2c"],
    responses={201: {"description": "Trame ajoutée"}, 400: {"description": "Données invalides"}}
)
def add_snmp_v2c(
    trame: PostTrameSNMPv2c,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Ajoute une trame SNMP v2c"""
    try:
        # Construction du contenu avec VarBinds
        contenu = trame.contenu or {"varbinds": []}
        
        success = db.ajouter_paquet_snmp(
            version_snmp="v2c",
            adresse_source=trame.source_ip,
            port_source=trame.source_port,
            adresse_dest=trame.dest_ip,
            port_dest=trame.dest_port,
            contenu=contenu,
            request_id=trame.request_id,
            error_status=trame.error_status,
            error_index=trame.error_index,
            communaute=trame.community,
            oid_racine=trame.oid_racine,
            type_pdu=trame.type_pdu,
            agent_snmp="FastAPI SNMP Monitor v2.0"
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de l'enregistrement de la trame"
            )
        
        return {
            "status": "success",
            "message": "Trame SNMP v2c enregistrée avec succès",
            "version": "v2c",
            "source": f"{trame.source_ip}:{trame.source_port}",
            "destination": f"{trame.dest_ip}:{trame.dest_port}",
            "oid_racine": trame.oid_racine,
            "request_id": trame.request_id,
            "authorized_by": api_key
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Erreur: {str(e)}"
        )

# ============================================================================
# ENDPOINTS - GESTION DES TRAMES SNMP v3
# ============================================================================

@app.post("/snmp/v3/add",
    summary="Ajouter une trame SNMP v3",
    description="Enregistre une trame SNMP v3 dans la base de données",
    tags=["Trames SNMP v3"],
    responses={201: {"description": "Trame ajoutée"}, 400: {"description": "Données invalides"}}
)
def add_snmp_v3(
    trame: PostTrameSNMPv3,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Ajoute une trame SNMP v3"""
    try:
        contenu = trame.contenu or {"varbinds": []}
        
        success = db.ajouter_paquet_snmp(
            version_snmp="v3",
            adresse_source=trame.source_ip,
            port_source=trame.source_port,
            adresse_dest=trame.dest_ip,
            port_dest=trame.dest_port,
            contenu=contenu,
            request_id=trame.request_id,
            error_status=trame.error_status,
            error_index=trame.error_index,
            oid_racine=trame.oid_racine,
            type_pdu=trame.type_pdu,
            agent_snmp="FastAPI SNMP Monitor v2.0",
            contexte_v3=trame.contexte,
            niveau_securite=trame.niveau_securite,
            utilisateur_v3=trame.utilisateur,
            engine_id=trame.engine_id,
            msg_id=trame.msg_id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de l'enregistrement de la trame"
            )
        
        return {
            "status": "success",
            "message": "Trame SNMP v3 enregistrée avec succès",
            "version": "v3",
            "source": f"{trame.source_ip}:{trame.source_port}",
            "destination": f"{trame.dest_ip}:{trame.dest_port}",
            "utilisateur": trame.utilisateur,
            "niveau_securite": trame.niveau_securite,
            "oid_racine": trame.oid_racine,
            "request_id": trame.request_id,
            "authorized_by": api_key
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Erreur: {str(e)}"
        )

# ============================================================================
# ENDPOINTS - CONSULTATION DES TRAMES SNMP
# ============================================================================

@app.get("/snmp/list",
    summary="Lister les trames SNMP",
    description="Retourne les trames SNMP enregistrées",
    tags=["Consultation Trames"]
)
def list_snmp_trames(
    limit: int = 100,
    version: Optional[str] = None,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Liste les trames SNMP"""
    trames = db.lister_paquets_snmp(limite=limit, version_snmp=version)
    
    return {
        "status": "success",
        "count": len(trames),
        "trames": trames,
        "authorized_by": api_key
    }

@app.get("/snmp/search",
    summary="Rechercher des trames SNMP",
    description="Recherche des trames selon des critères",
    tags=["Consultation Trames"]
)
def search_snmp_trames(
    adresse_source: Optional[str] = None,
    adresse_dest: Optional[str] = None,
    version_snmp: Optional[str] = None,
    oid_racine: Optional[str] = None,
    date_debut: Optional[str] = None,
    date_fin: Optional[str] = None,
    api_key: str = Depends(validate_api_key)
) -> Dict[str, Any]:
    """Recherche des trames SNMP"""
    try:
        trames = db.rechercher_paquets(
            adresse_source=adresse_source,
            adresse_dest=adresse_dest,
            version_snmp=version_snmp,
            oid_racine=oid_racine,
            date_debut=date_debut,
            date_fin=date_fin
        )
        
        return {
            "status": "success",
            "count": len(trames),
            "filtres": {
                "adresse_source": adresse_source,
                "adresse_dest": adresse_dest,
                "version_snmp": version_snmp,
                "oid_racine": oid_racine,
                "date_debut": date_debut,
                "date_fin": date_fin
            },
            "trames": trames,
            "authorized_by": api_key
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Erreur de recherche: {str(e)}"
        )

@app.get("/snmp/statistics",
    summary="Statistiques SNMP",
    description="Retourne les statistiques sur les trames SNMP",
    tags=["Consultation Trames"]
)
def snmp_statistics(api_key: str = Depends(validate_api_key)) -> Dict[str, Any]:
    """Retourne les statistiques"""
    stats = db.statistiques_paquets()
    
    return {
        "status": "success",
        "statistiques": stats,
        "authorized_by": api_key
    }

# ============================================================================
# ENDPOINTS - SANTÉ DE L'API
# ============================================================================

@app.get("/health",
    summary="État de l'API",
    description="Vérifie l'état de l'API et de la base de données",
    tags=["Système"]
)
def health_check() -> Dict[str, Any]:
    """Vérifie l'état de l'API"""
    try:
        # Tester la connexion à la BDD
        utilisateurs = db.lister_utilisateurs()
        cles_api = db.lister_cles_api(actives_seulement=True)
        stats = db.statistiques_paquets()
        
        return {
            "status": "healthy",
            "message": "API et base de données fonctionnelles",
            "database": "connected",
            "users_count": len(utilisateurs),
            "active_api_keys": len(cles_api),
            "total_packets": stats.get("total_paquets", 0)
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Erreur: {str(e)}",
            "database": "disconnected"
        }

# ============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="ssl/key.pem",
        ssl_certfile="ssl/fullcert.pem"
        )
