from django.contrib.auth.backends import BaseBackend
from django.db import connection
# Usamos la misma librería de hashing que la API
from lib.pwd import verify_password


class ApiUserBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Buscamos DIRECTAMENTE en la tabla 'usuarios' de la API
        with connection.cursor() as cursor:
            # La API usa 'nombre' como usuario y 'email' también sirve
            cursor.execute(
                "SELECT id, nombre, email, password, rol FROM usuarios WHERE nombre = %s OR email = %s",
                [username, username]
            )
            row = cursor.fetchone()

        if row:
            user_id, nombre, email, hashed_pw, rol = row
            # Verificamos la contraseña con el mismo hasher de la API (Argon2/Bcrypt)
            if verify_password(password, hashed_pw):
                # Creamos un objeto usuario "falso" pero válido para Django
                from django.contrib.auth import get_user_model
                User = get_user_model()
                user = User(id=user_id, username=nombre, email=email)
                # Sin is_staff/is_superuser: este usuario no tiene fila en
                # usuarios_usuario y /admin/ rompe al guardar (FK del log).
                user.rol = (rol or '').lower()
                return user
        return None

    def get_user(self, user_id):
        # Django necesita esto para mantener la sesión activa
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, nombre, email, rol FROM usuarios WHERE id = %s", [user_id])
            row = cursor.fetchone()

        if row:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User(id=row[0], username=row[1], email=row[2])
            user.rol = (row[3] or '').lower()
            return user
        return None
