from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import Usuario


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = Usuario
        fields = ['id', 'username', 'email', 'telefono', 'rol', 'password']
        read_only_fields = ['id']

    def create(self, validated_data):
        rol_seguro = validated_data.get('rol', Usuario.Rol.VISITANTE)
        if rol_seguro not in [Usuario.Rol.INQUILINO, Usuario.Rol.PROPIETARIO]:
            rol_seguro = Usuario.Rol.VISITANTE

        validated_data['password'] = make_password(validated_data['password'])
        validated_data['rol'] = rol_seguro
        return Usuario.objects.create(**validated_data)


class AdminCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = Usuario
        fields = ['id', 'username', 'email',
                  'telefono', 'rol', 'password', 'activo']

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return Usuario.objects.create(**validated_data)


class UsuarioResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = ['id', 'username', 'email',
                  'telefono', 'rol', 'activo', 'date_joined']
