import re
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Ideahistoria, HistorialdeArchivos

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email','password']
        extra_kwargs = {
            'password' : {'write_only' : True, 'min_length' : 8}
        }
    def validate_password(self, value):

        if not any(char.isupper() for char in value):
               raise serializers.ValidationError("La contraseña debe tener al menos una letra mayúscula")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
               raise serializers.ValidationError("La contraseña debe tener al menos un caracter especial")
        return value


    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este correto ya esta registrado")
        return value
    
    def create(self, validated_data):
        password = validated_data.pop('password',None)
        if not password:
            raise serializers.ValidationError({"password": "Este campo es obligatorio"})
        
        user = User(**validated_data)

        if password:
            user.set_password(password)
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
     email = serializers.EmailField()
     password = serializers.CharField(write_only=True)

     def validate(self, data):
          user = authenticate(email=data['email'], password=data['password'])
          if not user:
               raise serializers.ValidationError("Credenciales incorrectas")
          
          refresh = RefreshToken.for_user(user)
          return {
               'access': str(refresh.access_token),
               'refresh': str(refresh),
          }

class IdeahistoriaSerializer(serializers.ModelSerializer):
     class Meta:
          model = Ideahistoria
          fields = '__all__'
          read_only_fields = ['user']
     
class HistorialdeArchivosSerializer(serializers.ModelSerializer):
     class Meta:
          model = HistorialdeArchivos
          fields = '__all__'
          read_only_fields = ['user']