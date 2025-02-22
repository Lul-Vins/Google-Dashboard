import requests
from django.conf import settings
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload
from .utils import refresh_google_token
import json

def create_user_drive_folder(user):
    access_token = refresh_google_token(user)
    
    headers = {
        "Authorization": f"Bearer {access_token}", "Content-Type": "application/json",
    }

    data = {"name": f"Ideas_{user.email}",
            "mimeType": "application/vnd.google-apps.folder",}
    
    response = requests.post(
        "https://www.googleapis.com/drive/v3/files", json=data, headers=headers
    )
    folder_data = response.json()
    if "id" in folder_data:
        user.google_drive_folder_id = folder_data["id"]
        user.save()
    else:
        raise ValueError("No se pudo crear la carpeta en Google Drive")

def upload_idea_to_drive(user, idea_title, idea_content):
    """Sube la idea a Google Drive y guarda el id en la Base de datos"""
    if not user.google_drive_folder_id:
        folder_id= create_user_drive_folder(user)
    else:
        folder_id = user.google_drive_folder_id

    access_token = refresh_google_token(user)
    print(f"Nuevo access_token: {access_token}")

    headers = {
        "Authorization": f"Bearer {access_token}"  
    }

    file_metadata = {
        "name" : f"{idea_title}.txt",
        "parents": [folder_id],
        "mimeType": "text/plain"
    }

    files = {
        "metadata": (None, json.dumps(file_metadata), "application/json"),
        "file": (f"{idea_title}.txt", idea_content, "text/plain"),
    }

    response =response = requests.post(
        "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
        headers=headers,
        files=files,
    )
    return response.json()