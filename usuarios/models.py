import re
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError


class Usuario(AbstractUser):
    class Rol(models.TextChoices):
        ADMINISTRADOR = 'administrador', 'Administrador'
        PROPIETARIO = 'propietario', 'Propietario'
        INQUILINO = 'inquilino', 'Inquilino'
        VISITANTE = 'visitante', 'Visitante'

    email = models.EmailField(unique=True, max_length=150)
    telefono = models.CharField(max_length=11, blank=True, null=True)
    rol = models.CharField(
        max_length=20,
        choices=Rol.choices,
        default=Rol.VISITANTE
    )
    activo = models.BooleanField(default=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def clean(self):
        super().clean()
        if self.telefono and not re.match(r"^\d{4,5}-\d{4}$", self.telefono):
            raise ValidationError(
                {'telefono': 'Formato inválido: 0000-0000 o 00000-0000'})

    def save(self, *args, **kwargs):
        # Django guarda last_login con update_fields al iniciar sesión;
        # ese user es virtual (sin password) y no debe pasar full_clean.
        if not kwargs.get('update_fields'):
            self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.username} ({self.get_rol_display()})"


class UsuarioApi(models.Model):
    """Espejo de la tabla 'usuarios' que crea la API FastAPI.

    No es el modelo de autenticación de Django (Usuario), que vive en su
    propia tabla; sirve para ver y editar desde /admin/ la gente real.
    """

    class Rol(models.TextChoices):
        ADMINISTRADOR = 'administrador', 'Administrador'
        PROPIETARIO = 'propietario', 'Propietario'
        INQUILINO = 'inquilino', 'Inquilino'
        VISITANTE = 'visitante', 'Visitante'

    nombre = models.CharField(max_length=100)
    email = models.EmailField(unique=True, max_length=150)
    telefono = models.CharField(max_length=9, blank=True, null=True)
    rol = models.CharField(max_length=20, choices=Rol.choices,
                           default=Rol.VISITANTE)
    password = models.CharField(max_length=255)
    activo = models.BooleanField(default=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'usuarios'
        verbose_name = 'Usuario (API)'
        verbose_name_plural = 'Usuarios (API)'

    def __str__(self):
        return f"#{self.id} {self.nombre} ({self.rol})"
