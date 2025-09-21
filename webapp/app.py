
from flask import Flask, render_template
from keycloak import KeycloakOpenID
import os

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
    return "The login page is not implemented yet"


@app.route("/account")
def account():
    return "The account page is not implemented yet"


@app.route("/logout")
def logout():
    return "The logout page is not implemented yet"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=True)
