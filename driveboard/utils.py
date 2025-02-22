import requests
from django.conf import settings
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

def refresh_google_token(user):
    """El usuario obtiene un nuevo access token usando el refresh token de la base de datos"""

    if not user.google_refresh_token:
        raise ValueError("El usuario no tiene un refresh_token almacenado.")
    
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id" : settings.GOOGLE_CLIENT_ID,
        "client_secret" : settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": user.google_refresh_token,
        "grant_type" : "refresh_token",
    }

    response = requests.post(token_url, data=data)
    token_data = response.json()

    if "access_token" not in token_data:
        raise ValueError("No se pudo refrescar el token de acceso")
   
    return token_data["access_token"]