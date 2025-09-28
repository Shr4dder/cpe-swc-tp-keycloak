#!/usr/bin/env python3
import json
import sys
import urllib.request
import jwt
from jwt import InvalidSignatureError, DecodeError

JWKS_URL = "http://localhost:8080/realms/webapp/protocol/openid-connect/certs"

def fetch_jwks(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.load(resp)

def find_jwk(jwks: dict, kid: str) -> dict | None:
    for k in jwks.get("keys", []):
        if k.get("kid") == kid and k.get("use", "sig") == "sig":
            return k
    return None

def build_public_key_from_jwk(jwk: dict):
    # On couvre RSA (RS256/PS256…) et EC (ES256…), suffisants pour Keycloak.
    kty = jwk.get("kty")
    jwk_str = json.dumps(jwk)
    if kty == "RSA":
        from jwt.algorithms import RSAAlgorithm
        return RSAAlgorithm.from_jwk(jwk_str)
    elif kty == "EC":
        from jwt.algorithms import ECAlgorithm
        return ECAlgorithm.from_jwk(jwk_str)
    else:
        raise ValueError(f"Type de clé non pris en charge: {kty}")

def verify_signature_only(token: str, jwks_url: str = JWKS_URL) -> tuple[str, str]:
    # 1) Lire l’en-tête sans vérifier
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")
    kid = header.get("kid")
    if not kid:
        raise ValueError("Le JWT ne contient pas de 'kid' dans l’en-tête.")
    if not alg:
        raise ValueError("Le JWT ne contient pas d'algorithme ('alg') dans l’en-tête.")

    # 2) Récupérer la clé correspondante dans le JWKS
    jwks = fetch_jwks(jwks_url)
    jwk = find_jwk(jwks, kid)
    if not jwk:
        raise ValueError(f"Aucune clé 'sig' avec kid='{kid}' dans le JWKS.")

    # 3) Construire la clé publique à partir du JWK
    public_key = build_public_key_from_jwk(jwk)

    # 4) Décoder en ne vérifiant QUE la signature (pas iss/aud/exp)
    jwt.decode(
        token,
        key=public_key,
        algorithms=[alg],
        options={
            "verify_signature": True,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_iat": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
    return kid, alg

if __name__ == "__main__":
    # Usage: python verify_jwt_signature.py "<JWT_Ici>"
    token = sys.argv[1] if len(sys.argv) > 1 else input("Collez le JWT: ").strip()
    try:
        kid, alg = verify_signature_only(token, JWKS_URL)
        print("✅ Signature VALIDE")
        print(f"kid: {kid} | alg: {alg}")
        sys.exit(0)
    except InvalidSignatureError:
        print("❌ Signature INVALIDE (signature incorrecte)")
        sys.exit(1)
    except DecodeError as e:
        print(f"❌ Impossible de décoder le JWT: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Erreur: {e}")
        sys.exit(3)
