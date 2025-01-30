import os
from dotenv import load_dotenv
from .base import *

load_dotenv()

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "googledash",
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": "127.0.0.1",
        "PORT": "5432",
    }
}