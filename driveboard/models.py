from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings 

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("El email es obligatorio")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)

    objects = CustomUserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
    
    def get_full_name(self):
        return self.email
    def get_short_name(self):
        return self.email.split("@")[0]
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # Sin username, solo email y password

    def __str__(self):
        return self.email
    
class HistorialdeArchivos(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Relación con el modelo User
        on_delete=models.CASCADE,
        related_name='archivos_guardados'
    )
    archivo_nombre = models.CharField(max_length=255)  # Nombre del archivo guardado
    archivo_url = models.URLField()  # URL del archivo en Google Drive
    fecha_guardado = models.DateTimeField(auto_now_add=True)  # Fecha y hora en que se guardó

    def __str__(self):
        return f"Archivo {self.archivo_nombre} guardado por {self.user.email} el {self.fecha_guardado}"

class Ideahistoria(models.Model):
    user= models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='ideas_guardadas'
    )
    title_idea = models.CharField(max_length=255)
    descripcion = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title_idea
