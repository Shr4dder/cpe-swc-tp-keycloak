
from flask import Flask, render_template, redirect, session, request
from keycloak import KeycloakOpenID
import os
import secrets

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

keycloak_openid = KeycloakOpenID(server_url=os.getenv("KEYCLOAK_URL"),
                                 realm_name=os.getenv("KEYCLOAK_REALM"),
                                 client_id=os.getenv("KEYCLOAK_CLIENT_ID"),
                                 client_secret_key=os.getenv("KEYCLOAK_CLIENT_SECRET"))


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/login")
def login():
    # URL vers laquelle Keycloak doit rediriger l'utilisateur après la connexion
    auth_url  = keycloak_openid.auth_url( 
        redirect_uri="http://localhost:8081/callback", 
        scope="openid profile email" 
    )
    return redirect(auth_url)

@app.route("/logout")
def logout():
    token = session['token']
    # Utiliser le refresh token pour déconnecter l'utilisateur avec Keycloak
    keycloak_openid.logout(token["refresh_token"])
    session.clear()
    return redirect("/")

@app.route("/callback")
def callback():
    
    # Utiliser le code pour obtenir un token d'accès de Keycloak
    token = keycloak_openid.token(
        code=request.args.get('code'),
        grant_type="authorization_code",
        redirect_uri='http://localhost:8081/callback'
    )
    
    
    Info_utilisateur = keycloak_openid.userinfo(token["access_token"])
        
    # Sauvegarder le token dans la session (ou base de données selon le besoin)
    session['token'] = token
    session['Info_utilisateur'] = Info_utilisateur
    return redirect("/account")

@app.route("/account")
def account():
    # Vérifier si le token et les informations de l'utilisateur sont dans la session
    token = session['token']
    user_info = session['Info_utilisateur']

    # Décoder le access token pour obtenir les informations sur les rôles du realm
    decoded_token = keycloak_openid.decode_token(token["access_token"])
    realm_roles = decoded_token.get("realm_access", {}).get("roles", [])

    # Extraire les informations de l'utilisateur
    email = user_info.get('email')
    first_name = user_info.get('given_name')
    last_name = user_info.get('family_name')
        
    # Construire la réponse avec les informations demandées
    account_info = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token", "Non disponible"),
        "realm_roles": realm_roles,
        "email": email,
        "first_name": first_name,
        "last_name": last_name
    }

    return render_template("account_info.html", account_info=account_info)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=True)
