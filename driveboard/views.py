from rest_framework import generics, status, viewsets
import jwt
import requests
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.views import APIView
from .serializers import UserSerializer, LoginSerializer, IdeahistoriaSerializer, HistorialdeArchivosSerializer
from .models import User, Ideahistoria, HistorialdeArchivos
from rest_framework.permissions import AllowAny, IsAuthenticated
import os
from django.conf import settings
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
import json
from datetime import datetime,timedelta
from django.contrib.auth import get_user_model


class RegisterUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class =  UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        user.set_password(self.request.data['password'])
        user.save()
        return user

class LoginUserView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self,request, *args, **kwargms):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class IdeahistoriaView(viewsets.ModelViewSet):
    serializer_class = IdeahistoriaSerializer
    permission_classes = [IsAuthenticated]


    def get_queryset(self):
        return Ideahistoria.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class HistorialdeArchivosView(viewsets.ModelViewSet):
    serializer_class = HistorialdeArchivosSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self, request):
        return HistorialdeArchivosSerializer.objects.filter(user=request.user)
    

CLIENT_SECRETS_FILE = settings.GOOGLE_OAUTH_CREDENTIALS_JSON
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/drive']

def generate_jwt(user):
    """Genera un token JWT para el usuario autenticado con Google"""
    payload = {
        "user_id": user.id,
        "email": user.email,
        "exp": datetime.now() + timedelta(days=7)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def google_oauth(request):
    """Inicia el flujo de autenticación con Google OAuth 2.0"""
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, SCOPES,
        redirect_uri=request.build_absolute_uri(reverse('google_auth_callback'))
    )

    if 'code' not in request.GET:
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')

        request.session['state'] = state  # Protección CSRF
        return redirect(authorization_url)

    flow.fetch_token(authorization_response=request.get_full_path())
    credentials = flow.credentials
    request.session['google_credentials'] = credentials_to_dict(credentials)


def credentials_to_dict(credentials):
    """Convierte el objeto Credentials en un diccionario seguro"""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'client_id': credentials.client_id,
        'scopes': credentials.scopes
    }


def google_auth_callback(request):
    """Maneja la respuesta de Google después del login"""
    if 'error' in request.GET:
        return JsonResponse({'error': 'Error en la autenticación'}, status=400)

    # Verificación CSRF
    if request.session.get('state') != request.GET.get('state'):
        return JsonResponse({'error': 'Posible ataque CSRF detectado'}, status=403)

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, SCOPES,
        redirect_uri=request.build_absolute_uri(reverse('google_auth_callback'))
    )

    flow.fetch_token(authorization_response=request.get_full_path())

    credentials = flow.credentials

    # Obtener información del usuario desde Google
    response = requests.get(
        'https://www.googleapis.com/oauth2/v1/userinfo',
        headers={'Authorization': f'Bearer {credentials.token}'}
    )

    if response.status_code != 200:
        return JsonResponse({'error': 'Error obteniendo datos del usuario desde Google'}, status=400)

    user_info = response.json()
    email = user_info.get("email")
    name = user_info.get("name")

    if not email:
        return JsonResponse({'error': 'No se pudo obtener el email de Google'}, status=400)

    # Verificar si el usuario ya existe en la base de datos
    User = get_user_model()
    user, created = User.objects.get_or_create(email=email)

    # Generar un JWT para el usuario
    jwt_token = generate_jwt(user)

    return JsonResponse({
        "message": "Autenticación exitosa",
        "user": {"email": email, "name": name, "new_user": created},
        "token": jwt_token
    })




    
