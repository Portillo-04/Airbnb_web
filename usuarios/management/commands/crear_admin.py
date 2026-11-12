import re

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from lib.pwd import get_password_hash
from usuarios.models import UsuarioApi
from usuarios.utils import username_para_espejo


class Command(BaseCommand):
    help = ('Crea un administrador en la tabla "usuarios" que comparte con la '
            'API, o restablece la contraseña si ese email ya existe.')

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True)
        parser.add_argument('--password', required=True)
        parser.add_argument('--nombre', default=None)

    def handle(self, *args, **options):
        email = options['email'].strip().lower()
        password = options['password']
        nombre = (options['nombre'] or '').strip()

        if len(password) < 6:
            raise CommandError('La contraseña debe tener al menos 6 caracteres.')

        # La API guarda las claves con pwdlib (ver lib/pwd.py), no con Django.
        hashed = get_password_hash(password)
        ahora = timezone.now()

        with transaction.atomic():
            usuario = UsuarioApi.objects.filter(email=email).first()
            if usuario is None:
                usuario = UsuarioApi.objects.create(
                    nombre=nombre or 'Administrador',
                    email=email,
                    telefono=None,
                    rol='administrador',
                    password=hashed,
                    activo=True,
                    created_at=ahora,
                    updated_at=ahora)
                accion = 'creado'
            else:
                if usuario.rol != 'administrador':
                    self.stdout.write(self.style.WARNING(
                        f"'{email}' tenía el rol '{usuario.rol}'; ahora es "
                        'administrador.'))
                if nombre:
                    usuario.nombre = nombre
                usuario.rol = 'administrador'
                usuario.password = hashed
                usuario.activo = True
                usuario.updated_at = ahora
                usuario.save()
                accion = 'actualizado'

            # Espejo en Django: /admin/ exige is_staff/is_superuser y una fila
            # con la misma pk que la API.
            User = get_user_model()
            telefono = usuario.telefono
            if telefono and not re.match(r'^\d{4,5}-\d{4}$', telefono):
                telefono = None
            User.objects.filter(email=email).exclude(pk=usuario.pk).delete()
            User.objects.update_or_create(
                pk=usuario.pk,
                defaults={
                    'username': username_para_espejo(
                        User, usuario.nombre, email, usuario.pk),
                    'email': email,
                    'telefono': telefono,
                    'rol': User.Rol.ADMINISTRADOR,
                    'activo': True,
                    'is_active': True,
                    'password': make_password(password),
                    'is_staff': True,
                    'is_superuser': True,
                },
            )

        self.stdout.write(self.style.SUCCESS(
            f"Administrador '{email}' {accion}. "
            'Ya podés entrar en /login/ y en /admin/.'))
