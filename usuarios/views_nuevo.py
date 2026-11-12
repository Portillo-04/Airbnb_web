import requests
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.backends import BaseBackend
from django.conf import settings
from django.db import connection
from django import forms


# ==============================================================================
# FORMULARIO EXCLUSIVO PARA ADMIN (Permite los 4 roles)
# ==============================================================================
class AdminUserCreationForm(forms.Form):
    nombre = forms.CharField(
        label='Nombre de usuario',
        max_length=100,
        widget=forms.TextInput(
            attrs={'placeholder': 'Ej: nuevo_admin', 'class': 'vTextField'})
    )
    email = forms.EmailField(
        label='Correo electrónico',
        widget=forms.EmailInput(
            attrs={'placeholder': 'correo@ejemplo.com', 'class': 'vTextField'})
    )
    telefono = forms.CharField(
        label='Teléfono',
        max_length=20,
        required=False,
        widget=forms.TextInput(
            attrs={'placeholder': '2777-XXXX', 'class': 'vTextField'})
    )
    password = forms.CharField(
        label='Contraseña',
        widget=forms.PasswordInput(
            attrs={'placeholder': 'Mínimo 6 caracteres', 'class': 'vTextField'}),
        min_length=6
    )

    # Incluye 'administrador' a diferencia del registro público
    ROL_CHOICES = [
        ('propietario', 'Propietario'),
        ('inquilino', 'Inquilino'),
        ('administrador', 'Administrador'),
    ]
    rol = forms.ChoiceField(label='Rol del usuario', choices=ROL_CHOICES)


# ==============================================================================
# BACKEND DE AUTENTICACIÓN (Puente Django <-> tabla 'usuarios' de la API)
# ==============================================================================
class ApiUserBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        User = get_user_model()

        # Intento A: usuario guardado en Django
        try:
            user = User.objects.get(email=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            pass

        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            pass

        # Intento B: buscar DIRECTAMENTE en la tabla 'usuarios' de la API
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, nombre, email, password, rol FROM usuarios "
                "WHERE email = %s OR nombre = %s",
                [username, username]
            )
            row = cursor.fetchone()

        if row:
            user_id, nombre, email, hashed_pw, rol_db = row

            is_valid = False
            try:
                from lib.pwd import verify_password
                is_valid = verify_password(password, hashed_pw)
            except ImportError:
                from django.contrib.auth.hashers import check_password
                is_valid = check_password(password, hashed_pw)

            if is_valid:
                user_obj = User(id=user_id, username=nombre, email=email)
                user_obj.rol = (rol_db or '').lower()
                if user_obj.rol in ['administrador', 'admin', 'propietario']:
                    user_obj.is_staff = True
                    if user_obj.rol in ['administrador', 'admin']:
                        user_obj.is_superuser = True
                return user_obj

        return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id, nombre, email, rol FROM usuarios WHERE id = %s",
                    [user_id])
                row = cursor.fetchone()

            if row:
                user_obj = User(id=row[0], username=row[1], email=row[2])
                user_obj.rol = (row[3] or '').lower()
                if user_obj.rol in ['administrador', 'admin', 'propietario']:
                    user_obj.is_staff = True
                return user_obj
            return None


# ==============================================================================
# VISTAS DE AUTENTICACIÓN Y DASHBOARD
# ==============================================================================
def register_view(request):
    """Registro PÚBLICO: Solo permite Propietario e Inquilino"""
    if request.method == 'POST':
        rol_seleccionado = request.POST.get('rol', '')

        # SEGURIDAD: Bloquear intento de registrarse como admin desde web pública
        ROLES_PERMITIDOS = ['propietario', 'inquilino']
        if rol_seleccionado not in ROLES_PERMITIDOS:
            messages.error(request, "Rol no válido para registro público.")
            return redirect('usuarios:register')

        # Normalizar teléfono: la API exige 'XXXX-XXXX' (8 dígitos)
        digitos = ''.join(
            c for c in request.POST.get('telefono', '') if c.isdigit())
        if len(digitos) != 8:
            messages.error(
                request, "El teléfono debe tener 8 dígitos, ej: 0991-2345.")
            return render(request, 'usuarios/register.html')
        telefono = f"{digitos[:4]}-{digitos[4:]}"

        payload = {
            'nombre': (request.POST.get('username') or '').strip(),
            'email': (request.POST.get('email') or '').strip(),
            'telefono': telefono,
            'password': request.POST.get('password') or '',
            'rol': rol_seleccionado
        }

        if len(payload['nombre']) < 3:
            messages.error(
                request, "El nombre de usuario debe tener al menos 3 caracteres.")
            return render(request, 'usuarios/register.html')

        try:
            response = requests.post(
                f"{settings.API_BASE_URL}/usuarios/register",
                json=payload,
                timeout=5
            )

            if response.status_code == 201:
                messages.success(
                    request, '¡Cuenta creada exitosamente! Ya podés iniciar sesión.')
                return redirect('usuarios:custom-login')
            elif response.status_code == 400:
                messages.error(request, response.json().get(
                    'detail', 'El nombre o email ya está registrado.'))
            else:
                errors = response.json().get('detail', 'Error desconocido')
                if isinstance(errors, list):
                    first_error = errors[0] if errors else {}
                    msg = first_error.get('msg', str(first_error))
                    loc = first_error.get('loc', [])
                    field = loc[-1] if len(loc) > 0 else 'campo'
                    errors = f"Error en '{field}': {msg}"
                messages.error(request, f"Error al registrar: {errors}")

        except requests.exceptions.ConnectionError:
            messages.error(
                request, 'No se pudo conectar con la API. Verificá que esté corriendo en el puerto 8000.')
        except Exception as e:
            messages.error(request, f'Error inesperado: {str(e)}')

    return render(request, 'usuarios/register.html')


def custom_login_view(request):
    """Login personalizado que consume la API y guarda el token JWT"""
    if request.user.is_authenticated:
        return redirect('usuarios:dashboard')

    if request.method == 'POST':
        email = (request.POST.get('email') or
                 request.POST.get('username') or '').strip()
        password = request.POST.get('password') or ''

        try:
            response = requests.post(
                f"{settings.API_BASE_URL}/usuarios/login",
                data={"username": email, "password": password},
                timeout=5
            )
            if response.status_code == 200:
                token = response.json().get('access_token')
                user = ApiUserBackend().authenticate(
                    request, username=email, password=password)
                if user is None:
                    messages.error(
                        request,
                        "La API validó la sesión pero no se pudo cargar el usuario.")
                    return render(request, 'usuarios/login.html')

                login(request, user, backend='usuarios.views.ApiUserBackend')
                request.session['jwt_token'] = token
                next_url = request.GET.get('next') or '/'
                return redirect(next_url)
            elif response.status_code in (401, 403):
                messages.error(request, response.json().get(
                    'detail', 'Credenciales inválidas'))
            else:
                messages.error(request, 'Error al iniciar sesión en la API.')

        except requests.exceptions.ConnectionError:
            messages.error(
                request, 'No se pudo conectar con la API. Verificá que esté corriendo en el puerto 8000.')
        except Exception as e:
            messages.error(request, f'Error inesperado: {str(e)}')

    return render(request, 'usuarios/login.html')


@login_required
def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('usuarios:custom-login')


@login_required
def dashboard_view(request):
    """Panel principal según el rol del usuario"""
    return render(request, 'usuarios/dashboard.html')


def _obtener_de_api(request, ruta):
    token = request.session.get('jwt_token')
    if not token:
        return None
    try:
        resp = requests.get(
            f"{settings.API_BASE_URL}{ruta}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


@login_required
def ver_solicitudes_alquiler(request):
    solicitudes = _obtener_de_api(
        request, "/solicitudes-alquiler/propietario") or []
    return render(request, 'usuarios/solicitudes_alquiler.html',
                  {'solicitudes': solicitudes})


@login_required
def ver_solicitudes_visita(request):
    solicitudes = _obtener_de_api(
        request, "/solicitudes-visita/propietario") or []
    return render(request, 'usuarios/solicitudes_visita.html',
                  {'solicitudes': solicitudes})


@login_required
def admin_crear_usuario(request):
    """Alta de usuarios con cualquier rol (solo administrador) vía API"""
    if getattr(request.user, 'rol', None) != 'administrador':
        messages.error(
            request, "Solo los administradores pueden crear usuarios.")
        return redirect('usuarios:dashboard')

    form = AdminUserCreationForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        datos = form.cleaned_data

        digitos = ''.join(
            c for c in (datos.get('telefono') or '') if c.isdigit())
        telefono = None
        if digitos:
            if len(digitos) != 8:
                messages.error(
                    request,
                    "El teléfono debe tener 8 dígitos, ej: 0991-2345.")
                return render(
                    request, 'usuarios/crear_usuario.html', {'form': form})
            telefono = f"{digitos[:4]}-{digitos[4:]}"

        payload = {
            'nombre': datos['nombre'].strip(),
            'email': datos['email'].strip(),
            'telefono': telefono,
            'password': datos['password'],
            'rol': datos['rol']
        }

        try:
            response = requests.post(
                f"{settings.API_BASE_URL}/usuarios/admin",
                json=payload,
                headers={
                    "Authorization":
                        f"Bearer {request.session.get('jwt_token', '')}"
                },
                timeout=5
            )
            if response.status_code == 201:
                messages.success(
                    request,
                    f"Usuario '{datos['nombre']}' creado como {datos['rol']}.")
                return redirect('usuarios:admin-crear-usuario')
            else:
                messages.error(request, f"Error al crear: {response.json().get('detail', 'sin detalle')}")
        except requests.exceptions.ConnectionError:
            messages.error(
                request, 'No se pudo conectar con la API (puerto 8000).')
        except Exception as e:
            messages.error(request, f'Error inesperado: {str(e)}')

    return render(request, 'usuarios/crear_usuario.html', {'form': form})