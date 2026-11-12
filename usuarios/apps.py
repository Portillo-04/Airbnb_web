from django.apps import AppConfig


class UsuariosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'usuarios'

    def ready(self):
        # Los usuarios se autentican contra la tabla de la API (SQLModel),
        # no tienen fila en la tabla de Django, y update_last_login intentaría
        # escribirla y fallaría con "did not affect any rows".
        from django.contrib.auth.signals import user_logged_in
        user_logged_in.disconnect(dispatch_uid='update_last_login')
