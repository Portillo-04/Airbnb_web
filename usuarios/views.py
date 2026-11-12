import io
import json
import os
import base64
import requests
from datetime import date
from functools import wraps
from urllib.parse import quote
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.backends import BaseBackend
from django.conf import settings
from django.http import Http404, JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST
from django import forms

from .forms import AdminUserCreationForm
from .utils import username_para_espejo
from pagos.models import PagoPendiente
from pagos import paypal as paypal_api
from contratos.models import ContratoWeb, SolicitudAlquilerWeb
from mantenimiento.models import SolicitudMantenimientoWeb
from propiedades.models import EstadoPropiedadWeb


# ==============================================================================
# SESIÓN CON LA API: el token JWT que se guarda al iniciar sesión vive 30 minutos
# ==============================================================================
class TokenExpirado(Exception):
    """El JWT guardado por la web venció: la API lo emite para 30 minutos."""


def sesion_api_vigente(view_func):
    @wraps(view_func)
    def _wrapper(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except TokenExpirado:
            logout(request)
            messages.error(
                request,
                'Tu sesión expiró. Ingresá de nuevo para continuar.'
            )
            return redirect('usuarios:custom-login')
    return _wrapper


def rol_requerido(*roles):
    """Bloquea el acceso a módulos que no corresponden al rol del usuario."""
    def decorador(view_func):
        @wraps(view_func)
        def _wrapper(request, *args, **kwargs):
            if getattr(request.user, 'rol', None) not in roles:
                messages.error(
                    request, 'No tenés permiso para acceder a ese módulo.')
                return redirect('usuarios:dashboard')
            return view_func(request, *args, **kwargs)
        return _wrapper
    return decorador


def csrf_failure_view(request, reason=''):
    """Formulario con token viejo (volver atrás tras el login, otra pestaña).

    El POST igual se rechaza: solo se evita el 403 técnico devolviendo al
    formulario, que llega con un token nuevo.
    """
    messages.error(
        request,
        'La página venció por seguridad. Volvé a intentarlo.')
    destino = request.META.get('HTTP_REFERER') or '/'
    if not url_has_allowed_host_and_scheme(
            destino,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure()):
        destino = '/'
    return redirect(destino)


def _next_seguro(request):
    candidato = request.GET.get('next') or request.POST.get('next')
    if candidato and url_has_allowed_host_and_scheme(
            candidato,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure()):
        return candidato
    return ''


def _json_api(resp):
    """Cuerpo JSON de la API como dict, o None si no lo es.

    Si en el puerto de la API hay otra cosa (por ejemplo, otra instancia de
    Django), la respuesta es HTML y `resp.json()` revienta con
    "Expecting value: line 1 column 1 (char 0)".
    """
    try:
        datos = resp.json()
    except ValueError:
        return None
    return datos if isinstance(datos, dict) else None


def _respuesta_inesperada(resp):
    return (f'La API en {settings.API_BASE_URL} respondió algo que no es JSON '
            f'(HTTP {resp.status_code}). Verificá que el servidor '
            f'{settings.API_BASE_URL} esté en línea y con la base de datos '
            'operativa.')


def _decodificar_jwt(token):
    """Payload del JWT como dict (sin verificar firma: eso lo hace la API)."""
    try:
        partes = token.split('.')
        if len(partes) < 2:
            return {}
        parte = partes[1] + '=' * (-len(partes[1]) % 4)
        datos = json.loads(base64.urlsafe_b64decode(parte))
        return datos if isinstance(datos, dict) else {}
    except (ValueError, TypeError):
        return {}


# ==============================================================================
# BACKEND DE AUTENTICACIÓN (Puente Django <-> tabla 'usuarios' de la API)
# ==============================================================================
class ApiUserBackend(BaseBackend):
    @staticmethod
    def _login_api(username, password):
        """Token JWT que entrega la API, o None si la API rechaza el login."""
        try:
            resp = requests.post(
                f"{settings.API_BASE_URL}/usuarios/login",
                data={"username": username, "password": password},
                timeout=5
            )
        except requests.exceptions.RequestException:
            return None
        if resp.status_code != 200:
            return None
        return (_json_api(resp) or {}).get('access_token')

    def authenticate(self, request, username=None, password=None, token=None,
                     **kwargs):
        """Autentica contra la API y deja el espejo local que respalda la sesión.

        El login de la web ya obtuvo el token y lo pasa; otros llamados
        (por ejemplo /admin/) traen recién usuario y contraseña.
        """
        if not token and username and password:
            token = self._login_api(username, password)
        if not token:
            return None

        perfil = self._perfil_desde_token(token)
        if perfil is None:
            return None

        User = get_user_model()
        return self._espejo_en_django(
            User, perfil['id'], perfil['nombre'], perfil['email'],
            perfil['telefono'], perfil['rol'], perfil['activo'],
            password or '')

    @staticmethod
    def _perfil_desde_token(token):
        """Perfil del usuario a partir del JWT; la API completa los datos."""
        claims = _decodificar_jwt(token)
        api_id = claims.get('id') or claims.get('user_id')
        sub = claims.get('sub')
        if api_id is None and isinstance(sub, (int, str)) and str(sub).isdigit():
            api_id = sub
        if api_id is None:
            return None

        email = claims.get('email') or (
            sub if isinstance(sub, str) and '@' in sub else '')
        perfil = {
            'id': int(api_id),
            'nombre': claims.get('nombre') or email or '',
            'email': email,
            'telefono': '',
            'rol': claims.get('rol') or 'inquilino',
            'activo': True,
        }

        try:
            resp = requests.get(
                f"{settings.API_BASE_URL}/usuarios/{perfil['id']}",
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )
            datos = _json_api(resp) if resp.status_code == 200 else None
        except requests.exceptions.RequestException:
            datos = None
        if isinstance(datos, dict):
            perfil.update({
                'nombre': datos.get('nombre') or perfil['nombre'],
                'email': datos.get('email') or perfil['email'],
                'telefono': datos.get('telefono') or '',
                'rol': datos.get('rol') or perfil['rol'],
                'activo': datos.get('activo', True),
            })
        # Sin email no hay espejo válido (email es unique y obligatorio).
        return perfil if perfil['email'] else None

    
    def _espejo_en_django(self, User, api_id, nombre, email, telefono, rol_db,
                          activo, password):
        """Crea o actualiza la fila de Django que respalda la sesión.

        La pk es el id del usuario en la API: las vistas de la web pasan
        request.user.pk como usuario en los llamados, y /admin/ necesita una
        fila real porque django_admin_log.user_id es FK a esta tabla.
        """
        rol = (rol_db or '').lower()
        if rol not in User.Rol.values:
            rol = User.Rol.VISITANTE
        es_admin = rol == User.Rol.ADMINISTRADOR

        # 'nombre' puede repetirse o traer espacios/acentos; username es único
        # y el validador de Django solo acepta letras, números y @/./+/-/_.
        username = username_para_espejo(User, nombre, email, api_id)

        # Sobras de un espejo anterior (email repetido en otra pk) rompen el unique.
        User.objects.filter(email=email).exclude(pk=api_id).delete()

        user, _ = User.objects.update_or_create(
            pk=api_id,
            defaults={
                'username': username,
                'email': email,
                'telefono': telefono,
                'rol': rol,
                'activo': bool(activo),
                'is_active': bool(activo),
                # Sin contraseña (login por token) la fila queda inutilizable:
                # si no, ModelBackend aceptaría contraseña vacía.
                'password': make_password(password) if password
                else make_password(None),
                'is_staff': es_admin,
                'is_superuser': es_admin,
            }
        )
        return user

    def get_user(self, user_id):
        return get_user_model().objects.filter(pk=user_id).first()


# ==============================================================================
# VISTAS
# ==============================================================================
def register_view(request):
    """Registro PÚBLICO: Propietario, Inquilino o Visitante."""
    if request.method == 'POST':
        rol_seleccionado = request.POST.get('rol', '')

        # SEGURIDAD: El administrador solo se crea desde el panel interno.
        ROLES_PERMITIDOS = ['propietario', 'inquilino', 'visitante']
        if rol_seleccionado not in ROLES_PERMITIDOS:
            messages.error(request, "Rol no válido para registro público.")
            return render(request, 'usuarios/register.html',
                          {'next': _next_seguro(request)})

        # Normalizar teléfono: la API exige 'XXXX-XXXX' (8 dígitos)
        digitos = ''.join(
            c for c in request.POST.get('telefono', '') if c.isdigit())
        if len(digitos) != 8:
            messages.error(
                request, "El teléfono debe tener 8 dígitos, ej: 0991-2345.")
            return render(request, 'usuarios/register.html',
                          {'next': _next_seguro(request)})
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
            return render(request, 'usuarios/register.html',
                          {'next': _next_seguro(request)})

        try:
            response = requests.post(
                f"{settings.API_BASE_URL}/usuarios/register",
                json=payload,
                timeout=5
            )

            if response.status_code == 201:
                messages.success(
                    request, '¡Cuenta creada exitosamente! Ya podés iniciar sesión.')
                destino = reverse('usuarios:custom-login')
                next_url = _next_seguro(request)
                if next_url:
                    return redirect(f"{destino}?next={quote(next_url, safe='')}")
                return redirect(destino)
            elif response.status_code == 400:
                datos = _json_api(response)
                if datos is None:
                    messages.error(request, _respuesta_inesperada(response))
                else:
                    messages.error(request, datos.get(
                        'detail', 'El nombre o email ya está registrado.'))
            else:
                datos = _json_api(response)
                if datos is None:
                    messages.error(request, _respuesta_inesperada(response))
                else:
                    errors = datos.get('detail', 'Error desconocido')
                    if isinstance(errors, list):
                        first_error = errors[0] if errors else {}
                        msg = first_error.get('msg', str(first_error))
                        loc = first_error.get('loc', [])
                        field = loc[-1] if len(loc) > 0 else 'campo'
                        errors = f"Error en '{field}': {msg}"
                    messages.error(request, f"Error al registrar: {errors}")

        except requests.exceptions.ConnectionError:
            messages.error(
                request, _api_indisponible())
        except Exception as e:
            messages.error(request, f'Error inesperado: {str(e)}')

    return render(request, 'usuarios/register.html',
                  {'next': _next_seguro(request)})


def custom_login_view(request):
    """Login personalizado que consume la API y guarda el token JWT"""
    if request.user.is_authenticated:
        return redirect(_next_seguro(request) or reverse('usuarios:dashboard'))

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
                token = (_json_api(response) or {}).get('access_token')
                if not token:
                    messages.error(request, _respuesta_inesperada(response))
                    return render(request, 'usuarios/login.html',
                                  {'next': _next_seguro(request)})
                user = ApiUserBackend().authenticate(
                    request, username=email, password=password, token=token)
                if user is None:
                    messages.error(
                        request,
                        "La API validó la sesión pero no se pudo cargar el usuario.")
                    return render(request, 'usuarios/login.html',
                  {'next': _next_seguro(request)})

                login(request, user, backend='usuarios.views.ApiUserBackend')
                request.session['jwt_token'] = token
                return redirect(_next_seguro(request) or '/')
            elif response.status_code in (401, 403):
                messages.error(request, (_json_api(response) or {}).get(
                    'detail', 'Credenciales inválidas'))
            else:
                messages.error(request, 'Error al iniciar sesión en la API.')

        except requests.exceptions.ConnectionError:
            messages.error(
                request, _api_indisponible())
        except Exception as e:
            messages.error(request, f'Error inesperado: {str(e)}')

    return render(request, 'usuarios/login.html',
                  {'next': _next_seguro(request)})


@login_required
def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('usuarios:custom-login')


@sesion_api_vigente
def dashboard_view(request):
    """Panel principal según el rol; para anónimos, el catálogo público."""
    if not request.user.is_authenticated:
        return catalogo_view(request)

    rol = getattr(request.user, 'rol', None)
    stats = []
    try:
        if rol in ('propietario', 'administrador'):
            props = _propiedades_api(request)
            cons = _contratos_visibles(request)
            mans = _obtener_de_api(request, "/mantenimiento/") or []
            stats = [
                {'num': len(props), 'label': 'Propiedades',
                 'icon': 'fa-house-chimney', 'bg': 'bg-blue',
                 'url': '/propiedades/'},
                {'num': len([c for c in cons if c.get('estado') == 'activo']),
                 'label': 'Contratos activos',
                 'icon': 'fa-file-signature', 'bg': 'bg-green',
                 'url': '/contratos/'},
            ]
            # Solicitudes de alquiler sobre las propiedades del propietario.
            if rol == 'propietario':
                mias = {p.get('id') for p in _mis_propiedades_api(request)}
                sols = [s for s in (_obtener_de_api(
                    request, "/solicitudes-alquiler/") or [])
                    if s.get('propiedad_id') in mias]
                stats.append(
                    {'num': len([s for s in sols if s.get('estado') == 'PENDIENTE']),
                     'label': 'Sol. Alquiler pendientes',
                     'icon': 'fa-handshake-simple', 'bg': 'bg-purple',
                     'url': '/solicitudes-alquiler/'})
            else:
                stats.append(
                    {'num': len([p for p in props
                                 if p.get('estado') == 'DISPONIBLE']),
                     'label': 'Viviendas disponibles',
                     'icon': 'fa-key', 'bg': 'bg-blue',
                     'url': '/propiedades/'})
            stats += [
                {'num': len([m for m in mans if m.get(
                    'estado') in ('pendiente', 'en_proceso')]),
                 'label': 'Mantenimiento abierto', 'icon': 'fa-screwdriver-wrench',
                 'bg': 'bg-red', 'url': '/mantenimiento/'},
            ]
            if rol == 'administrador':
                stats.append(
                    {'num': len(cons), 'label': 'Contratos totales',
                     'icon': 'fa-chart-column', 'bg': 'bg-indigo',
                     'url': '/reportes/'})
        elif rol == 'inquilino':
            cons = _contratos_visibles(request)
            activos = [c for c in cons if c.get('estado') == 'activo']
            disp = _obtener_de_api(request, "/propiedades/disponibles") or []
            npagos = 0
            for c in cons:
                npagos += len(_obtener_de_api(
                    request, f"/pagos/contrato/{c['id']}") or [])
            abiertas = [
                s for s in (_obtener_de_api(request, "/mantenimiento/") or [])
                if s.get('inquilino_id') == request.user.pk
                and (s.get('estado') or '').lower() in ('pendiente', 'en_proceso')
            ]
            stats = [
                {'num': len(activos), 'label': 'Contratos activos',
                 'icon': 'fa-file-signature', 'bg': 'bg-green',
                 'url': '/contratos/'},
                {'num': len({c.get('propiedad_id') for c in activos}),
                 'label': 'Mi vivienda',
                 'icon': 'fa-house-chimney', 'bg': 'bg-blue',
                 'url': '/propiedades/'},
                {'num': len(disp), 'label': 'Viviendas disponibles',
                 'icon': 'fa-key', 'bg': 'bg-purple',
                 'url': '#viviendas-disponibles'},
                {'num': npagos, 'label': 'Pagos registrados',
                 'icon': 'fa-credit-card', 'bg': 'bg-orange',
                 'url': '/pagos/'},
                {'num': len(abiertas), 'label': 'Mantenimiento abierto',
                 'icon': 'fa-screwdriver-wrench', 'bg': 'bg-red',
                 'url': '/mantenimiento/'},
            ]
        else:
            disp = _obtener_de_api(request, "/propiedades/disponibles") or []
            stats = [
                {'num': len(disp), 'label': 'Viviendas disponibles',
                 'icon': 'fa-house-chimney', 'bg': 'bg-blue',
                 'url': reverse('usuarios:catalogo-panel')},
            ]
    except TokenExpirado:
        raise
    except Exception:
        stats = []
    contexto = {'stats': stats}
    if getattr(request.user, 'rol', None) == 'inquilino':
        catalogo = _contexto_catalogo(request)
        catalogo['catalogo_url'] = reverse('usuarios:dashboard')
        catalogo['en_panel'] = True
        contexto['catalogo'] = catalogo
    return render(request, 'usuarios/dashboard.html', contexto)


def _alta_usuario_api(request, form):
    """Crea el usuario en la API. Devuelve None si salió bien, o el error."""
    datos = form.cleaned_data
    digitos = ''.join(c for c in (datos.get('telefono') or '') if c.isdigit())
    if digitos and len(digitos) != 8:
        return 'El teléfono debe tener 8 dígitos, ej: 0991-2345.'
    payload = {
        'nombre': datos['nombre'].strip(),
        'email': datos['email'].strip(),
        'telefono': f"{digitos[:4]}-{digitos[4:]}" if digitos else None,
        'password': datos['password'],
        'rol': datos['rol'],
    }
    resp = _enviar_a_api(request, "/usuarios/admin", payload)
    if resp is not None and resp.status_code == 201:
        if not datos.get('activo'):
            try:
                creado_id = resp.json().get('id')
            except Exception:
                creado_id = None
            if creado_id:
                _enviar_a_api(
                    request, f"/usuarios/{creado_id}",
                    {'activo': False}, method='PATCH')
        messages.success(
            request,
            f"Usuario '{payload['nombre']}' creado como {payload['rol']}.")
        return None
    return f"Error al crear: {_detalle_error(resp)}"


def _url_abs_api(valor):
    """Convierte una ruta relativa de la API (/uploads/...) en URL absoluta.

    El servidor guarda rutas relativas; la web y el móvil deben agregar el
    host de la API para que la imagen/PDF cargue desde cualquier dispositivo.
    """
    if not valor or not isinstance(valor, str):
        return valor
    if valor.startswith(('http://', 'https://')):
        return valor
    base = settings.API_BASE_URL.rstrip('/')
    return f"{base}/{valor.lstrip('/')}"


def _normalizar_api(datos):
    """Recorre la respuesta y deja las URLs de medios absolutas.

    La API del servidor manda `imagen_url`; se deja también como `fotos_url`
    por compatibilidad con versiones anteriores.
    """
    if isinstance(datos, list):
        return [_normalizar_api(i) for i in datos]
    if isinstance(datos, dict):
        for clave in ('imagen_url', 'fotos_url', 'pdf_url'):
            if datos.get(clave):
                datos[clave] = _url_abs_api(datos[clave])
        if not datos.get('imagen_url') and datos.get('fotos_url'):
            datos['imagen_url'] = datos['fotos_url']
        return {k: _normalizar_api(v) for k, v in datos.items()}
    return datos


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
        if resp.status_code == 401:
            raise TokenExpirado()
        if resp.status_code == 200:
            return _normalizar_api(resp.json())
        return None
    except TokenExpirado:
        raise
    except Exception:
        return None


def _obtener_publico(ruta):
    """GET sin token para el catálogo público del visitante."""
    try:
        resp = requests.get(f"{settings.API_BASE_URL}{ruta}", timeout=5)
        if resp.status_code == 200:
            return _normalizar_api(resp.json())
    except Exception:
        pass
    return None


def _usuarios_api(request):
    """Todos los usuarios según la API (lista de dicts), o [] si no hay."""
    datos = _obtener_de_api(request, "/usuarios/")
    return datos if isinstance(datos, list) else []


def _mapa_nombres(request):
    return {u.get('id'): u.get('nombre', '') for u in _usuarios_api(request)}


ESTADOS_VIVIENDA = ('DISPONIBLE', 'ALQUILADA', 'MANTENIMIENTO')


def _aplicar_estados_locales(props):
    """Superpone los cambios guardados en la web cuando la API falló.

    Se aplica campo por campo (estado, dirección, descripción, precio) y la
    copia local se descarta solo cuando la API ya devuelve todos esos valores.
    """
    if not isinstance(props, list):
        return props
    por_id = {p.get('id'): p for p in props if isinstance(p, dict)}
    for local in EstadoPropiedadWeb.objects.all():
        p = por_id.get(local.propiedad_id)
        if p is None:
            continue
        iguales = True
        if local.estado:
            if (p.get('estado') or '').upper() != local.estado:
                p['estado'] = local.estado
                p['estado_local'] = True
                iguales = False
        if local.direccion:
            if (p.get('direccion') or '') != local.direccion:
                p['direccion'] = local.direccion
                p['datos_locales'] = True
                iguales = False
        if local.descripcion:
            if (p.get('descripcion') or '') != local.descripcion:
                p['descripcion'] = local.descripcion
                p['datos_locales'] = True
                iguales = False
        if local.precio_mensual is not None:
            if float(p.get('precio_mensual') or 0) != float(local.precio_mensual):
                p['precio_mensual'] = float(local.precio_mensual)
                p['datos_locales'] = True
                iguales = False
        if iguales:
            local.delete()
    return props


def _guardar_estado_local(propiedad_id, estado, datos=None):
    if estado not in ESTADOS_VIVIENDA:
        return
    datos = datos or {}
    defaults = {'estado': estado}
    for campo in ('direccion', 'descripcion', 'precio_mensual'):
        if campo in datos:
            defaults[campo] = datos.get(campo)
    EstadoPropiedadWeb.objects.update_or_create(
        propiedad_id=propiedad_id, defaults=defaults)


def _quitar_estado_local(propiedad_id):
    EstadoPropiedadWeb.objects.filter(propiedad_id=propiedad_id).delete()


def _datos_vivienda_con_estado(propiedad, estado):
    """Ficha completa para el PUT de la API (no acepta solo el estado).

    El servidor actual responde 500 cuando el formulario trae únicamente
    `estado`; se mandan los mismos campos que usa la edición de viviendas.
    """
    datos = {
        'direccion': propiedad.get('direccion') or '',
        'departamento': propiedad.get('departamento') or '',
        'distrito': propiedad.get('distrito') or '',
        'descripcion': propiedad.get('descripcion') or '',
        'precio_mensual': float(propiedad.get('precio_mensual') or 0),
        'estado': estado,
    }
    if propiedad.get('propietario_id'):
        datos['propietario_id'] = propiedad.get('propietario_id')
    return datos


def _propiedades_api(request):
    """Propiedades que la API entrega al rol autenticado."""
    return _propiedades_segun_rol(request)


def _propiedades_segun_rol(request):
    """Viviendas visibles según el rol.

    `/propiedades/` es el listado general; para dueños e inquilinos la API
    puede restringirlo, así que se prueban los endpoints propios de cada rol.
    """
    rol = getattr(request.user, 'rol', None)
    if rol == 'propietario':
        rutas = ('/propiedades/mis-propiedades', '/propiedades/')
    elif rol == 'inquilino':
        rutas = ('/propiedades/mis-propiedades-alquiladas', '/propiedades/')
    else:
        rutas = ('/propiedades/',)
    for ruta in rutas:
        datos = _obtener_de_api(request, ruta)
        if isinstance(datos, list):
            return _aplicar_estados_locales(datos)
    return []


def _mis_propiedades_api(request):
    """Propiedades del propietario autenticado (endpoint propio de la API)."""
    datos = _obtener_de_api(request, "/propiedades/mis-propiedades")
    return _aplicar_estados_locales(datos) if isinstance(datos, list) else []


def _contexto_catalogo(request):
    """Datos y filtros del catálogo de viviendas disponibles."""
    datos = _obtener_publico('/propiedades/disponibles')
    api_ok = isinstance(datos, list)
    propiedades = datos if api_ok else []

    q = (request.GET.get('q') or '').strip()
    precio_min = request.GET.get('precio_min') or ''
    precio_max = request.GET.get('precio_max') or ''
    orden = request.GET.get('orden') or ''
    con_foto = request.GET.get('con_foto') == '1'

    if q:
        aguja = q.lower()
        propiedades = [
            p for p in propiedades
            if aguja in (p.get('direccion') or '').lower()
            or aguja in (p.get('descripcion') or '').lower()
        ]
    if precio_min:
        try:
            minimo = float(precio_min)
            propiedades = [p for p in propiedades
                           if float(p.get('precio_mensual') or 0) >= minimo]
        except ValueError:
            precio_min = ''
    if precio_max:
        try:
            maximo = float(precio_max)
            propiedades = [p for p in propiedades
                           if float(p.get('precio_mensual') or 0) <= maximo]
        except ValueError:
            precio_max = ''
    if con_foto:
        propiedades = [p for p in propiedades if p.get('imagen_url')]
    if orden == 'precio_asc':
        propiedades.sort(key=lambda p: float(p.get('precio_mensual') or 0))
    elif orden == 'precio_desc':
        propiedades.sort(
            key=lambda p: float(p.get('precio_mensual') or 0), reverse=True)
    elif orden == 'recientes':
        propiedades.sort(
            key=lambda p: str(p.get('created_at') or ''), reverse=True)

    return {
        'propiedades': propiedades,
        'api_ok': api_ok,
        'api_base': settings.API_BASE_URL,
        'q': q,
        'precio_min': precio_min,
        'precio_max': precio_max,
        'orden': orden,
        'con_foto': con_foto,
    }


def catalogo_view(request):
    """Catálogo público de viviendas disponibles (Visitante)."""
    contexto = _contexto_catalogo(request)
    contexto['catalogo_url'] = reverse('usuarios:catalogo')
    return render(request, 'usuarios/catalogo.html', contexto)


@login_required
@rol_requerido('inquilino')
def catalogo_panel_view(request):
    """Catálogo de viviendas disponibles dentro del panel del inquilino."""
    contexto = _contexto_catalogo(request)
    contexto['catalogo_url'] = reverse('usuarios:catalogo-panel')
    contexto['en_panel'] = True
    return render(request, 'usuarios/catalogo_panel.html', contexto)


def catalogo_detalle_view(request, pk):
    """Ficha pública de una vivienda disponible y solicitud de visita."""
    datos = _obtener_publico('/propiedades/disponibles')
    api_ok = isinstance(datos, list)
    propiedad = next((p for p in (datos or []) if p.get('id') == pk), None)
    if not propiedad:
        raise Http404('La vivienda no está disponible.')

    destino_login = reverse('usuarios:custom-login')
    next_url = quote(request.path, safe='')

    if request.method == 'POST':
        if not request.user.is_authenticated:
            return redirect(f"{destino_login}?next={next_url}")
        if getattr(request.user, 'rol', None) != 'inquilino':
            messages.error(
                request,
                'Solo las cuentas de inquilino pueden coordinar visitas.')
            return redirect('usuarios:catalogo-detalle', pk=pk)
        if not request.session.get('jwt_token'):
            logout(request)
            messages.error(
                request,
                'Tu sesión expiró. Ingresá de nuevo para enviar la solicitud.')
            return redirect(f"{destino_login}?next={next_url}")

        mensaje = (request.POST.get('mensaje') or '').strip()
        if not mensaje:
            messages.error(
                request, 'Escribí un mensaje para el propietario.')
            return redirect('usuarios:catalogo-detalle', pk=pk)

        fecha_txt = (request.POST.get('fecha') or '').strip()
        try:
            fecha = date.fromisoformat(fecha_txt) if fecha_txt else date.today()
        except ValueError:
            messages.error(request, 'La fecha propuesta no es válida.')
            return redirect('usuarios:catalogo-detalle', pk=pk)

        payload = {
            'propiedad_id': pk,
            'visitante_id': request.user.pk,
            'fecha_solicitada': f'{fecha.isoformat()}T00:00:00',
            'mensaje': mensaje[:500],
        }
        try:
            resp = _enviar_a_api(request, '/solicitudes-visita/', payload)
        except TokenExpirado:
            logout(request)
            messages.error(
                request,
                'Tu sesión expiró. Ingresá de nuevo para enviar la solicitud.')
            return redirect(f"{destino_login}?next={next_url}")

        if resp is not None and resp.status_code == 201:
            messages.success(
                request,
                'Solicitud enviada. El propietario se pondrá en contacto.')
        else:
            messages.error(
                request,
                f'No se pudo enviar la solicitud: {_detalle_error(resp)}')
        return redirect('usuarios:catalogo-detalle', pk=pk)

    return render(request, 'usuarios/catalogo_detalle.html', {
        'propiedad': propiedad,
        'api_base': settings.API_BASE_URL,
        'api_ok': api_ok,
        'volver_url': (
            reverse('usuarios:catalogo-panel')
            if (request.user.is_authenticated
                and getattr(request.user, 'rol', None) == 'inquilino')
            else reverse('usuarios:catalogo')),
        'puede_solicitar': (
            request.user.is_authenticated
            and getattr(request.user, 'rol', None) == 'inquilino'),
        'login_url': f"{destino_login}?next={next_url}",
        'registro_url': (
            f"{reverse('usuarios:register')}?next={next_url}"),
    })


def _fecha_iso(valor):
    """Fecha de un input date o datetime ISO; None si no es válida."""
    try:
        return date.fromisoformat(str(valor or '')[:10])
    except ValueError:
        return None


def _solicitud_alquiler_local_dict(solicitud):
    """Fila de la copia local con la forma que usa la plantilla."""
    estado = (solicitud.estado or 'PENDIENTE').upper()
    return {
        'id': solicitud.api_id or solicitud.pk,
        'api_id': solicitud.api_id,
        'propiedad_id': solicitud.propiedad_id,
        'propiedad_direccion': solicitud.propiedad_direccion,
        'inquilino_id': solicitud.inquilino_id,
        'inquilino_nombre': solicitud.inquilino_nombre,
        'fecha_inicio': solicitud.fecha_inicio.isoformat(),
        'fecha_fin': solicitud.fecha_fin.isoformat(),
        'estado': estado,
        'respuesta_propietario': solicitud.respuesta_propietario,
        'local': True,
    }


def _solicitud_alquiler_igual(local, api):
    """¿La copia local coincide con lo que devuelve la API?"""
    return (
        (local.estado or '').upper() == (api.get('estado') or '').upper()
        and (local.respuesta_propietario or '').strip()
        == (api.get('respuesta_propietario') or '').strip()
        and local.fecha_inicio.isoformat()
        == str(api.get('fecha_inicio'))[:10]
        and local.fecha_fin.isoformat()
        == str(api.get('fecha_fin'))[:10])


def _guardar_solicitud_alquiler_web(api_id, propiedad_id, direccion,
                                    inquilino_id, inquilino_nombre,
                                    inicio, fin, estado, respuesta=None,
                                    sin_confirmar=False):
    """Crea o actualiza la copia local de una solicitud de alquiler.

    `sin_confirmar=True` marca los cambios que la API no confirmó: esos
    valores se muestran por encima de lo que devuelva el listado.
    """
    fila = None
    if api_id:
        fila = SolicitudAlquilerWeb.objects.filter(api_id=api_id).first()
    if fila is None:
        return SolicitudAlquilerWeb.objects.create(
            api_id=api_id,
            propiedad_id=propiedad_id or 0,
            propiedad_direccion=(direccion or '')[:255],
            inquilino_id=inquilino_id or 0,
            inquilino_nombre=(inquilino_nombre or '')[:150],
            fecha_inicio=inicio,
            fecha_fin=fin,
            estado=(estado or 'PENDIENTE').upper()[:20],
            respuesta_propietario=(respuesta or '')[:500],
            pendiente_sync=sin_confirmar)
    fila.propiedad_id = propiedad_id or fila.propiedad_id
    fila.propiedad_direccion = (direccion or fila.propiedad_direccion)[:255]
    fila.inquilino_id = inquilino_id or fila.inquilino_id
    fila.inquilino_nombre = (inquilino_nombre or fila.inquilino_nombre)[:150]
    fila.fecha_inicio = inicio or fila.fecha_inicio
    fila.fecha_fin = fin or fila.fecha_fin
    fila.estado = (estado or fila.estado).upper()[:20]
    if respuesta is not None:
        fila.respuesta_propietario = (respuesta or '')[:500]
    fila.pendiente_sync = sin_confirmar
    fila.save()
    return fila


def _reintentar_solicitudes_alquiler(request):
    """Reenvía a la API los pedidos que quedaron solo en la web.

    Si el servidor estaba caído al crearlos, no tienen id. Al abrir la
    lista se reintenta (pocos por vez); si la API los acepta, la copia
    adopta el id y deja de quedar pendiente.
    """
    pendientes = SolicitudAlquilerWeb.objects.filter(
        inquilino_id=request.user.pk, api_id__isnull=True,
        estado='PENDIENTE')[:3]
    for local in pendientes:
        resp = _enviar_a_api(request, "/solicitudes-alquiler/", {
            'propiedad_id': local.propiedad_id,
            'inquilino_id': request.user.pk,
            'fecha_inicio': f'{local.fecha_inicio.isoformat()}T00:00:00Z',
            'fecha_fin': f'{local.fecha_fin.isoformat()}T00:00:00Z',
        })
        if resp is None or resp.status_code != 201:
            continue
        datos = _json_api(resp) or {}
        local.api_id = datos.get('id') or local.api_id
        local.estado = (datos.get('estado') or local.estado).upper()[:20]
        local.pendiente_sync = False
        local.save(update_fields=['api_id', 'estado', 'pendiente_sync'])


@login_required
@sesion_api_vigente
@rol_requerido('propietario', 'inquilino')
def ver_solicitudes_alquiler(request):
    rol = getattr(request.user, 'rol', None)

    if request.method == 'POST':
        accion = request.POST.get('accion')
        if accion == 'crear':
            if rol != 'inquilino':
                messages.error(
                    request,
                    'Solo un inquilino puede pedir un alquiler desde la web.')
                return redirect('usuarios:solicitudes-alquiler')

            try:
                propiedad_id = int(request.POST.get('propiedad_id') or 0)
            except (TypeError, ValueError):
                propiedad_id = 0
            inicio = _fecha_iso(request.POST.get('fecha_inicio'))
            fin = _fecha_iso(request.POST.get('fecha_fin'))
            if propiedad_id <= 0 or inicio is None or fin is None:
                messages.error(
                    request,
                    'Elegí una vivienda disponible y las fechas de la '
                    'solicitud.')
                return redirect('usuarios:solicitudes-alquiler')
            if fin <= inicio:
                # La API exige que el fin sea estrictamente posterior.
                messages.error(
                    request,
                    'La fecha de fin debe ser posterior a la de inicio.')
                return redirect('usuarios:solicitudes-alquiler')

            payload = {
                'propiedad_id': propiedad_id,
                # El servidor actual exige inquilino_id y datetimes con zona
                # horaria (SQLModel rechaza los naive con error 500).
                'inquilino_id': request.user.pk,
                'fecha_inicio': f'{inicio.isoformat()}T00:00:00Z',
                'fecha_fin': f'{fin.isoformat()}T00:00:00Z',
            }
            resp = _enviar_a_api(request, "/solicitudes-alquiler/", payload)
            creada = resp is not None and resp.status_code in (200, 201)
            fallo_servidor = resp is None or resp.status_code >= 500
            datos = (_json_api(resp) or {}) if creada else {}
            direccion = ''
            for p in (_obtener_de_api(request, "/propiedades/disponibles")
                      or []):
                if p.get('id') == propiedad_id:
                    direccion = p.get('direccion') or ''
                    break
            if creada or fallo_servidor:
                # El servidor responde 500 al crear solicitudes; la copia
                # local permite que el pedido no se pierda y llegue al
                # propietario desde esta web.
                _guardar_solicitud_alquiler_web(
                    datos.get('id') if creada else None,
                    propiedad_id, direccion, request.user.pk,
                    request.user.username, inicio, fin,
                    datos.get('estado') or 'PENDIENTE',
                    sin_confirmar=fallo_servidor)
            if creada:
                messages.success(
                    request,
                    'Solicitud enviada. El propietario puede responderla.')
            elif fallo_servidor:
                messages.warning(
                    request,
                    'El servidor no pudo registrar la solicitud '
                    f'({_detalle_error(resp)}) pero quedó guardada en esta '
                    'web y ya aparece en la lista.')
            else:
                messages.error(request, f"Error: {_detalle_error(resp)}")

        elif accion == 'responder':
            if rol != 'propietario':
                messages.error(
                    request,
                    'Solo el propietario responde las solicitudes de alquiler.')
                return redirect('usuarios:solicitudes-alquiler')
            sol_id = request.POST.get('solicitud_id')
            api_id = (request.POST.get('api_id') or '').strip()
            nuevo_estado = (
                request.POST.get('nuevo_estado') or '').strip().upper()
            if nuevo_estado not in ('APROBADA', 'RECHAZADA', 'POSPUESTA',
                                    'PENDIENTE'):
                messages.error(request, 'Estado de la solicitud inválido.')
                return redirect('usuarios:solicitudes-alquiler')
            respuesta = (request.POST.get('respuesta') or '').strip()[:500]
            try:
                propiedad_id = int(request.POST.get('propiedad_id') or 0)
            except (TypeError, ValueError):
                propiedad_id = 0
            try:
                inquilino_id = int(request.POST.get('inquilino_id') or 0)
            except (TypeError, ValueError):
                inquilino_id = 0
            inquilino_nombre = (
                request.POST.get('inquilino_nombre') or '')[:150]
            direccion = (request.POST.get('propiedad_direccion') or '')[:255]
            inicio = _fecha_iso(request.POST.get('fecha_inicio'))
            fin = _fecha_iso(request.POST.get('fecha_fin'))

            propias = {p.get('id') for p in _propiedades_api(request)}
            local = None
            if api_id:
                local = SolicitudAlquilerWeb.objects.filter(
                    api_id=int(api_id)).first()
            elif sol_id:
                try:
                    local = SolicitudAlquilerWeb.objects.filter(
                        pk=int(sol_id)).first()
                except (TypeError, ValueError):
                    local = None
            if ((propiedad_id and propiedad_id not in propias)
                    or (local and local.propiedad_id not in propias)):
                messages.error(
                    request, 'Esa solicitud no pertenece a tus viviendas.')
                return redirect('usuarios:solicitudes-alquiler')

            if api_id:
                payload = {'estado': nuevo_estado}
                if respuesta:
                    payload['respuesta_propietario'] = respuesta
                resp = _enviar_a_api(
                    request, f"/solicitudes-alquiler/{api_id}",
                    payload, method='PATCH')
                if resp is not None and resp.status_code == 200:
                    if local:
                        local.estado = nuevo_estado
                        local.respuesta_propietario = respuesta
                        # La respuesta ya está en la API; se mantiene hasta
                        # que el listado la devuelva igual (y la confirme).
                        local.pendiente_sync = True
                        local.save(update_fields=[
                            'estado', 'respuesta_propietario',
                            'pendiente_sync'])
                    messages.success(
                        request, f"Solicitud #{api_id} actualizada a "
                        f"{nuevo_estado}.")
                elif resp is None or resp.status_code >= 500:
                    if local:
                        local.estado = nuevo_estado
                        local.respuesta_propietario = respuesta
                        local.pendiente_sync = True
                        local.save(update_fields=[
                            'estado', 'respuesta_propietario',
                            'pendiente_sync'])
                    elif inicio and fin and propiedad_id and inquilino_id:
                        local = _guardar_solicitud_alquiler_web(
                            int(api_id), propiedad_id, direccion,
                            inquilino_id, inquilino_nombre, inicio, fin,
                            nuevo_estado, respuesta, sin_confirmar=True)
                    if local:
                        messages.warning(
                            request,
                            'El servidor no respondió '
                            f'({_detalle_error(resp)}); la respuesta quedó '
                            'guardada en esta web.')
                    else:
                        messages.error(
                            request,
                            'El servidor no respondió '
                            f'({_detalle_error(resp)}) y no se pudo guardar '
                            'la respuesta: faltan datos de la solicitud.')
                else:
                    messages.error(request, f"Error: {_detalle_error(resp)}")
            else:
                if local is None:
                    messages.error(
                        request,
                        'No se encontró la solicitud de alquiler.')
                else:
                    local.estado = nuevo_estado
                    local.respuesta_propietario = respuesta
                    local.pendiente_sync = True
                    local.save(update_fields=[
                        'estado', 'respuesta_propietario',
                        'pendiente_sync'])
                    if nuevo_estado == 'APROBADA':
                        messages.success(
                            request,
                            'Solicitud aprobada en esta web. El contrato no '
                            'se creó porque el servidor no registró el '
                            'pedido; reintentá cuando el servidor vuelva.')
                    else:
                        messages.success(
                            request,
                            f'Solicitud #{local.pk} actualizada a '
                            f'{nuevo_estado}.')
        return redirect('usuarios:solicitudes-alquiler')

    mis_viviendas = []
    disponibles = []
    if rol == 'inquilino':
        _reintentar_solicitudes_alquiler(request)
    prop_map = {p.get('id'): p.get('direccion', '')
                for p in _propiedades_api(request)}
    todas = _obtener_de_api(request, "/solicitudes-alquiler/")
    lista_no_disponible = todas is None
    todas = todas if isinstance(todas, list) else []
    if rol == 'propietario':
        mis_viviendas = _mis_propiedades_api(request)
        if not todas:
            # Algunas versiones de la API exponen el listado propio del
            # propietario en otra ruta; si el general viene vacío se prueba.
            otras = _obtener_de_api(
                request, "/solicitudes-alquiler/propietario")
            if isinstance(otras, list):
                todas = otras
        mias = {p.get('id') for p in mis_viviendas}
        solicitudes = [s for s in todas if s.get('propiedad_id') in mias]
    else:
        solicitudes = [s for s in todas
                       if s.get('inquilino_id') == request.user.pk]
        disponibles = _obtener_de_api(request, "/propiedades/disponibles") or []

    api_por_id = {s.get('id'): s for s in solicitudes}
    locales = SolicitudAlquilerWeb.objects.all()
    if rol == 'inquilino':
        locales = locales.filter(inquilino_id=request.user.pk)
    else:
        locales = locales.filter(propiedad_id__in=list(prop_map))
    for local in locales:
        if local.api_id and local.api_id in api_por_id:
            fila_api = api_por_id[local.api_id]
            if not local.pendiente_sync:
                # Espejo: los datos de la API mandan y actualizan la copia.
                inicio_api = _fecha_iso(fila_api.get('fecha_inicio'))
                fin_api = _fecha_iso(fila_api.get('fecha_fin'))
                local.estado = (fila_api.get('estado')
                                or local.estado).upper()[:20]
                local.respuesta_propietario = (
                    fila_api.get('respuesta_propietario') or '')[:500]
                if inicio_api:
                    local.fecha_inicio = inicio_api
                if fin_api:
                    local.fecha_fin = fin_api
                local.save(update_fields=[
                    'estado', 'respuesta_propietario',
                    'fecha_inicio', 'fecha_fin'])
                continue
            if _solicitud_alquiler_igual(local, fila_api):
                local.pendiente_sync = False
                local.save(update_fields=['pendiente_sync'])
                continue
            # La copia local tiene una respuesta que la API no confirmó.
            fila = _solicitud_alquiler_local_dict(local)
            solicitudes[solicitudes.index(fila_api)] = fila
            continue
        if not local.api_id:
            # Se guardó sin id porque el alta falló; si la API ya la lista,
            # se adopta el id de la fila equivalente para no duplicarla.
            gemela = next((
                s for s in solicitudes
                if s.get('inquilino_id') == local.inquilino_id
                and s.get('propiedad_id') == local.propiedad_id
                and str(s.get('fecha_inicio'))[:10]
                == local.fecha_inicio.isoformat()
                and str(s.get('fecha_fin'))[:10]
                == local.fecha_fin.isoformat()
            ), None)
            if gemela and not gemela.get('local'):
                local.api_id = gemela.get('id')
                local.save(update_fields=['api_id'])
                continue
        solicitudes.append(_solicitud_alquiler_local_dict(local))

    for s in solicitudes:
        s['propiedad_direccion'] = (
            s.get('propiedad_direccion')
            or prop_map.get(s.get('propiedad_id'), ''))
    return render(request, 'usuarios/solicitudes_alquiler.html', {
        'solicitudes': solicitudes,
        'disponibles': disponibles,
        'api_base': settings.API_BASE_URL,
        'es_propietario': rol == 'propietario',
        'es_inquilino': rol == 'inquilino',
        'mis_viviendas': mis_viviendas,
        'lista_no_disponible': lista_no_disponible,
    })


@login_required
@sesion_api_vigente
@rol_requerido('propietario')
def ver_solicitudes_visita(request):
    """Solicitudes de visita recibidas; el propietario las responde."""
    if request.method == 'POST':
        sol_id = request.POST.get('solicitud_id')
        nuevo_estado = request.POST.get('nuevo_estado')
        payload = {'estado': nuevo_estado}
        respuesta = (request.POST.get('respuesta') or '').strip()
        if respuesta:
            payload['respuesta_propietario'] = respuesta
        resp = _enviar_a_api(
            request, f"/solicitudes-visita/{sol_id}", payload, method='PATCH')
        if resp is not None and resp.status_code == 200:
            messages.success(
                request,
                f"Solicitud #{sol_id} actualizada a {nuevo_estado}.")
        else:
            messages.error(request, f"Error: {_detalle_error(resp)}")
        return redirect('usuarios:solicitudes-visita')

    todas = _obtener_de_api(request, "/solicitudes-visita/") or []
    mias = {p.get('id') for p in _mis_propiedades_api(request)}
    solicitudes = [s for s in todas if s.get('propiedad_id') in mias]
    prop_map = {p.get('id'): p.get('direccion', '')
                for p in _propiedades_api(request)}
    nombres = _mapa_nombres(request)
    for s in solicitudes:
        s['propiedad_direccion'] = prop_map.get(s.get('propiedad_id'), '')
        s['visitante_nombre'] = nombres.get(
            s.get('visitante_id'), f"Usuario #{s.get('visitante_id')}")
    return render(request, 'usuarios/solicitudes_visita.html',
                  {'solicitudes': solicitudes})


@login_required
@sesion_api_vigente
@rol_requerido('inquilino')
def mis_solicitudes_visita(request):
    """Solicitudes de visita enviadas por el inquilino, con la respuesta."""
    todas = _obtener_de_api(request, "/solicitudes-visita/") or []
    solicitudes = [s for s in todas
                   if s.get('visitante_id') == request.user.pk]
    prop_map = {p.get('id'): p.get('direccion', '')
                for p in _propiedades_api(request)}
    for s in solicitudes:
        s['propiedad_direccion'] = prop_map.get(s.get('propiedad_id'), '')
    return render(request, 'usuarios/mis_visitas.html',
                  {'solicitudes': solicitudes})


# ==============================================================================
# MÓDULOS: PROPIEDADES / CONTRATOS / PAGOS / MANTENIMIENTO (consumen la API)
# ==============================================================================

def _enviar_a_api(request, ruta, payload=None, method='POST', params=None):
    token = request.session.get('jwt_token')
    if not token:
        return None
    try:
        resp = requests.request(
            method,
            f"{settings.API_BASE_URL}{ruta}",
            json=payload,
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        if resp.status_code == 401:
            raise TokenExpirado()
        return resp
    except TokenExpirado:
        raise
    except requests.exceptions.RequestException:
        return None


def _enviar_multipart_api(request, ruta, datos, archivo=None, method='POST'):
    """POST/PUT multipart de la API: campo `datos` (JSON) + `file` opcional.

    Así crea y actualiza propiedades el servidor (y guarda la foto en su
    propio /uploads, no en la web).
    """
    token = request.session.get('jwt_token')
    if not token:
        return None
    files = None
    if archivo is not None:
        archivo.seek(0)
        files = {'file': (archivo.name, archivo.read(),
                          archivo.content_type or 'application/octet-stream')}
    try:
        resp = requests.request(
            method,
            f"{settings.API_BASE_URL}{ruta}",
            data={'datos': json.dumps(datos)},
            files=files,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        if resp.status_code == 401:
            raise TokenExpirado()
        return resp
    except TokenExpirado:
        raise
    except requests.exceptions.RequestException:
        return None


def _api_indisponible():
    return (f'No se pudo conectar con la API del servidor en '
            f'{settings.API_BASE_URL}. Verificá que el servidor esté en línea.')


def _detalle_error(resp):
    if resp is None:
        return _api_indisponible()
    try:
        data = resp.json()
    except Exception:
        data = None
    detalle = data.get('detail') if isinstance(data, dict) else None
    if isinstance(detalle, list):
        # Error de validación (422): primer mensaje con su campo.
        primero = detalle[0] if detalle else {}
        if isinstance(primero, dict):
            campo = (primero.get('loc') or ['campo'])[-1]
            detalle = f"{campo}: {primero.get('msg', primero)}"
        else:
            detalle = str(primero)
    if detalle:
        if resp.status_code >= 500:
            return (f'El servidor falló con un error interno (HTTP '
                    f'{resp.status_code}): {detalle}')
        return str(detalle)
    if resp.status_code >= 500:
        return (f'El servidor respondió HTTP {resp.status_code} (error '
                'interno). Revisá la base de datos y los logs del servidor.')
    return str(data) if data is not None else f'Código {resp.status_code}'


def _contrato_web_dict(c):
    """Fila local de ContratoWeb con la forma que esperan las plantillas."""
    return {
        'id': c.api_id,
        'propiedad_id': c.propiedad_id,
        'inquilino_id': c.inquilino_id,
        'fecha_inicio': c.fecha_inicio.isoformat(),
        'fecha_fin': c.fecha_fin.isoformat(),
        'precio_mensual': float(c.precio_mensual),
        'estado': c.estado,
        'pdf_url': c.pdf_url or None,
        'propiedad_direccion': c.propiedad_direccion,
        'inquilino_nombre': c.inquilino_nombre,
    }


def _guardar_contrato_web(contrato):
    """Guarda/actualiza la copia local de un contrato de la API."""
    if not isinstance(contrato, dict) or not contrato.get('id'):
        return
    try:
        fila = ContratoWeb.objects.filter(api_id=contrato['id']).first()
        if fila is None:
            fila = ContratoWeb(api_id=contrato['id'])
        fila.propiedad_id = contrato.get('propiedad_id') or fila.propiedad_id or 0
        fila.inquilino_id = contrato.get('inquilino_id') or fila.inquilino_id or 0
        if contrato.get('fecha_inicio'):
            fila.fecha_inicio = str(contrato['fecha_inicio'])[:10]
        if contrato.get('fecha_fin'):
            fila.fecha_fin = str(contrato['fecha_fin'])[:10]
        if contrato.get('precio_mensual') is not None:
            fila.precio_mensual = contrato['precio_mensual']
        if contrato.get('estado'):
            fila.estado = contrato['estado']
        if contrato.get('pdf_url'):
            fila.pdf_url = contrato['pdf_url']
        if contrato.get('propiedad_direccion'):
            fila.propiedad_direccion = contrato['propiedad_direccion'][:255]
        if contrato.get('inquilino_nombre'):
            fila.inquilino_nombre = contrato['inquilino_nombre'][:150]
        fila.save()
    except (TypeError, ValueError):
        return


def _contratos_locales(request, rol):
    """Contratos guardados por la web cuando la API no deja listarlos."""
    filas = ContratoWeb.objects.all()
    if rol == 'inquilino':
        filas = filas.filter(inquilino_id=request.user.pk)
    elif rol == 'propietario':
        ids = {p.get('id') for p in _propiedades_api(request)}
        filas = filas.filter(propiedad_id__in=ids)
    contratos = [_contrato_web_dict(c) for c in filas]
    props = {p.get('id'): p.get('direccion', '')
             for p in _propiedades_api(request)}
    for c in contratos:
        c['propiedad_direccion'] = (c.get('propiedad_direccion')
                                    or props.get(c.get('propiedad_id'), ''))
        if rol == 'inquilino' and not c.get('inquilino_nombre'):
            c['inquilino_nombre'] = request.user.username
    return contratos


def _contratos_visibles(request):
    """Contratos según el rol: propios (propietario/inquilino) o todos (admin)."""
    rol = getattr(request.user, 'rol', None)
    contratos = _obtener_de_api(request, "/contratos/") or []
    if not contratos:
        # La API responde 403 a inquilinos/propietarios: se usa la copia
        # que dejó el administrador al abrir Contratos.
        return _contratos_locales(request, rol)
    props = {p.get('id'): p.get('direccion', '')
             for p in _propiedades_api(request)}
    for c in contratos:
        c['propiedad_direccion'] = props.get(c.get('propiedad_id'), '')
        _guardar_contrato_web(c)
    if rol == 'propietario':
        ids = {p.get('id') for p in _propiedades_api(request)}
        contratos = [c for c in contratos if c.get('propiedad_id') in ids]
    elif rol == 'inquilino':
        contratos = [c for c in contratos
                     if c.get('inquilino_id') == request.user.pk]
    return contratos


def _contrato_activo_de(request, propiedad_id):
    """Contrato vigente sobre una propiedad (regla: no puede estar DISPONIBLE)."""
    for c in (_obtener_de_api(request, "/contratos/") or []):
        if c.get('propiedad_id') == propiedad_id and c.get('estado') == 'activo':
            return c
    return None


def _contrato_referencia_de(request, propiedad_id):
    """Cualquier contrato del historial de la propiedad, vigente o no.

    La API no puede borrar una vivienda con contratos porque la FK lo impide
    (responde 500 sin detalle útil), así que se advierte antes de intentar.
    """
    for c in (_obtener_de_api(request, "/contratos/") or []):
        if c.get('propiedad_id') == propiedad_id:
            return c
    return None


def _propiedades_visibles(request):
    """Viviendas que corresponden al rol (la API ya filtra por rol)."""
    return _propiedades_api(request)


def _propietarios_para_select(request):
    """Propietarios activos según la API, como dicts {id, nombre, email}."""
    propietarios = [
        u for u in _usuarios_api(request)
        if (u.get('rol') or '').lower() == 'propietario' and u.get('activo')
    ]
    propietarios.sort(key=lambda u: (u.get('nombre') or '').lower())
    return propietarios


def _validar_imagen(foto):
    """Lanza ValueError si el archivo no es una imagen raster segura."""
    if not (foto.content_type or '').startswith('image/'):
        raise ValueError('El archivo no es una imagen.')
    # Solo formatos raster: un SVG con scripts servido desde este dominio
    # sería una vía de XSS almacenado.
    extension = os.path.splitext(foto.name)[1].lower()
    if extension not in {'.jpg', '.jpeg', '.png', '.webp', '.gif'}:
        raise ValueError('Formato no permitido: usá JPG, PNG, WEBP o GIF.')
    try:
        from PIL import Image
        Image.open(foto).verify()
        foto.seek(0)
    except ImportError:
        pass
    except Exception:
        raise ValueError('El archivo no es una imagen válida.')


def _validar_pdf(archivo):
    """Devuelve un mensaje de error, o None si el archivo es un PDF válido."""
    if archivo.size > 10 * 1024 * 1024:
        return 'El PDF no puede superar los 10 MB.'
    if os.path.splitext(archivo.name)[1].lower() != '.pdf':
        return 'El documento debe ser un archivo PDF.'
    cabecera = archivo.read(5)
    archivo.seek(0)
    if cabecera != b'%PDF-':
        return 'El archivo no parece un PDF válido.'
    return None


def _subir_pdf_api(request, contrato_id, archivo):
    """Sube el PDF firmado de un contrato (POST /contratos/upload-pdf).

    La API exige `contrato_id` + `file` y lo asigna al contrato; si además
    devuelve una ruta, se confirma con un PATCH de `pdf_url`.
    Devuelve (subido, ruta_o_None).
    """
    token = request.session.get('jwt_token')
    if not token:
        return False, None
    archivo.seek(0)
    try:
        resp = requests.post(
            f"{settings.API_BASE_URL}/contratos/upload-pdf",
            data={'contrato_id': contrato_id},
            files={'file': (archivo.name, archivo.read(), 'application/pdf')},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30)
        if resp.status_code == 401:
            raise TokenExpirado()
        if resp.status_code not in (200, 201):
            return False, None
        datos = resp.json()
    except TokenExpirado:
        raise
    except (requests.exceptions.RequestException, ValueError):
        return False, None
    if isinstance(datos, str):
        return True, datos
    if isinstance(datos, dict):
        for clave in ('pdf_url', 'url', 'ruta', 'path', 'file_url',
                      'archivo', 'documento'):
            if datos.get(clave):
                return True, datos[clave]
    return True, None


@login_required
@sesion_api_vigente
@rol_requerido('administrador', 'propietario', 'inquilino')
def modulo_propiedades(request):
    rol = getattr(request.user, 'rol', None)
    es_admin = rol == 'administrador'
    puede_gestionar = es_admin

    if request.method == 'POST':
        accion = request.POST.get('accion')

        if accion in ('estado', 'editar', 'eliminar'):
            if not puede_gestionar:
                messages.error(
                    request, 'No tenés permiso para modificar viviendas.')
                return redirect('usuarios:propiedades')

            try:
                pid = int(request.POST.get('propiedad_id') or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid <= 0:
                messages.error(request, 'Vivienda inválida.')
                return redirect('usuarios:propiedades')

            if accion == 'estado':
                nuevo = request.POST.get('estado')
                if nuevo not in ESTADOS_VIVIENDA:
                    messages.error(request, 'Estado de vivienda inválido.')
                    return redirect('usuarios:propiedades')
                vivienda = next(
                    (p for p in _propiedades_api(request)
                     if p.get('id') == pid), None)
                if vivienda is None:
                    messages.error(request, 'Esa vivienda no existe.')
                    return redirect('usuarios:propiedades')
                if nuevo == 'DISPONIBLE' and _contrato_activo_de(request, pid):
                    messages.error(
                        request,
                        f'La vivienda #{pid} tiene un contrato activo: no puede '
                        'pasar a DISPONIBLE. Finalizalo en Contratos primero.')
                    return redirect('usuarios:propiedades')
                resp = _enviar_multipart_api(
                    request, f"/propiedades/{pid}",
                    _datos_vivienda_con_estado(vivienda, nuevo),
                    method='PUT')
                if resp is not None and resp.status_code == 200:
                    _quitar_estado_local(pid)
                    messages.success(
                        request, f'Vivienda #{pid} ahora está {nuevo}.')
                elif resp is None or resp.status_code >= 500:
                    _guardar_estado_local(pid, nuevo)
                    messages.warning(
                        request,
                        f'El servidor no respondió '
                        f'({_detalle_error(resp)}); la vivienda #{pid} quedó '
                        f'marcada como {nuevo} en esta web.')
                else:
                    messages.error(request, f"Error: {_detalle_error(resp)}")

            elif accion == 'editar':
                owner_id = request.POST.get('propietario_id')
                owners = {str(u['id']) for u in _propietarios_para_select(request)}
                if owner_id and str(owner_id) not in owners:
                    messages.error(
                        request, 'El propietario seleccionado no es válido.')
                    return redirect('usuarios:propiedades')

                try:
                    precio = float(request.POST.get('precio_mensual') or 0)
                except (TypeError, ValueError):
                    precio = 0
                datos = {
                    'direccion': (request.POST.get('direccion') or '').strip(),
                    'departamento': (request.POST.get('departamento') or '').strip(),
                    'distrito': (request.POST.get('distrito') or '').strip(),
                    'descripcion': (request.POST.get('descripcion') or '').strip(),
                    'precio_mensual': precio,
                }
                if owner_id:
                    datos['propietario_id'] = int(owner_id)
                foto = request.FILES.get('foto')
                if foto:
                    try:
                        _validar_imagen(foto)
                    except ValueError as exc:
                        messages.error(request, str(exc))
                        return redirect('usuarios:propiedades')
                resp = _enviar_multipart_api(
                    request, f"/propiedades/{pid}", datos, archivo=foto,
                    method='PUT')
                if resp is not None and resp.status_code == 200:
                    messages.success(request, f'Vivienda #{pid} actualizada.')
                elif resp is None or resp.status_code >= 500:
                    vivienda = next(
                        (p for p in _propiedades_api(request)
                         if p.get('id') == pid), None)
                    if vivienda:
                        _guardar_estado_local(
                            pid, (vivienda.get('estado')
                                  or 'DISPONIBLE').upper(), datos)
                        messages.warning(
                            request,
                            f'El servidor no respondió '
                            f'({_detalle_error(resp)}); los cambios de la '
                            f'vivienda #{pid} quedaron guardados en esta web.')
                    else:
                        messages.error(
                            request,
                            f'El servidor no respondió '
                            f'({_detalle_error(resp)}) y no se pudo leer la '
                            f'vivienda #{pid}: los cambios no se guardaron.')
                else:
                    messages.error(request, f"Error: {_detalle_error(resp)}")

            else:
                referencia = _contrato_referencia_de(request, pid)
                if referencia:
                    messages.error(
                        request,
                        f'No se puede eliminar la vivienda #{pid}: tiene historial '
                        f'de contratos (contrato #{referencia.get("id")}, '
                        f'{referencia.get("estado")}). La API no permite borrar '
                        'viviendas referenciadas; dejala sin estado disponible '
                        'o desactivada.')
                    return redirect('usuarios:propiedades')
                resp = _enviar_a_api(
                    request, f"/propiedades/{pid}", method='DELETE')
                if resp is not None and resp.status_code == 204:
                    _quitar_estado_local(pid)
                    messages.success(request, f'Vivienda #{pid} eliminada.')
                else:
                    messages.error(request, f"Error: {_detalle_error(resp)}")

            return redirect('usuarios:propiedades')

        if not puede_gestionar:
            messages.error(
                request, 'No tenés permiso para crear viviendas.')
            return redirect('usuarios:propiedades')

        owner_id = request.POST.get('propietario_id')
        owners = {str(u['id']) for u in _propietarios_para_select(request)}
        if not owner_id or str(owner_id) not in owners:
            messages.error(
                request, 'Elegí un propietario válido para la vivienda.')
            return redirect('usuarios:propiedades')

        try:
            precio = float(request.POST.get('precio_mensual') or 0)
        except (TypeError, ValueError):
            precio = 0
        datos = {
            'direccion': (request.POST.get('direccion') or '').strip(),
            'departamento': (request.POST.get('departamento') or '').strip(),
            'distrito': (request.POST.get('distrito') or '').strip(),
            'descripcion': (request.POST.get('descripcion') or '').strip(),
            'precio_mensual': precio,
            'estado': 'DISPONIBLE',
            'propietario_id': int(owner_id),
        }
        foto = request.FILES.get('foto')
        if foto:
            try:
                _validar_imagen(foto)
            except ValueError as exc:
                messages.error(request, str(exc))
                return redirect('usuarios:propiedades')
        resp = _enviar_multipart_api(
            request, "/propiedades/", datos, archivo=foto)
        if resp is not None and resp.status_code in (200, 201):
            messages.success(request, "Propiedad creada correctamente.")
        else:
            messages.error(request, f"Error: {_detalle_error(resp)}")
        return redirect('usuarios:propiedades')

    propiedades = _propiedades_visibles(request)
    contratos = _obtener_de_api(request, "/contratos/") or []
    alquiladas = {c.get('propiedad_id') for c in contratos
                  if c.get('estado') == 'activo'}
    con_contratos = {c.get('propiedad_id') for c in contratos}
    propietarios = _propietarios_para_select(request) if es_admin else []
    nombres = _mapa_nombres(request) if es_admin else {}
    for p in propiedades:
        p['propietario_nombre'] = nombres.get(p.get('propietario_id'), '')
    return render(request, 'usuarios/propiedades.html', {
        'propiedades': propiedades,
        'api_base': settings.API_BASE_URL,
        'puede_gestionar': puede_gestionar,
        'es_admin': es_admin,
        'alquiladas': alquiladas,
        'con_contratos': con_contratos,
        'propietarios': propietarios,
    })


@login_required
@sesion_api_vigente
@rol_requerido('administrador', 'propietario', 'inquilino')
def modulo_contratos(request):
    # El contrato nace al aprobar una solicitud de alquiler; desde acá el
    # administrador adjunta el PDF y cierra contratos.
    rol = getattr(request.user, 'rol', None)
    es_admin = rol == 'administrador'

    if request.method == 'POST':
        accion = request.POST.get('accion')
        if accion == 'nuevo':
            if not es_admin:
                messages.error(
                    request, 'Solo el administrador crea contratos.')
                return redirect('usuarios:contratos')
            try:
                propiedad_id = int(request.POST.get('propiedad_id') or 0)
                inquilino_id = int(request.POST.get('inquilino_id') or 0)
                precio = float(request.POST.get('precio_mensual') or 0)
            except (TypeError, ValueError):
                propiedad_id = inquilino_id = 0
                precio = 0
            fecha_inicio = (request.POST.get('fecha_inicio') or '').strip()
            fecha_fin = (request.POST.get('fecha_fin') or '').strip()
            if (propiedad_id <= 0 or inquilino_id <= 0 or precio <= 0
                    or not fecha_inicio or not fecha_fin):
                messages.error(
                    request,
                    'Completá vivienda, inquilino, fechas y un precio mayor '
                    'a cero.')
                return redirect('usuarios:contratos')
            try:
                if date.fromisoformat(fecha_fin) < date.fromisoformat(
                        fecha_inicio):
                    messages.error(
                        request, 'La fecha de fin no puede ser anterior al '
                                 'inicio del contrato.')
                    return redirect('usuarios:contratos')
            except ValueError:
                messages.error(request, 'Las fechas del contrato no son '
                                        'válidas.')
                return redirect('usuarios:contratos')
            payload = {
                'propiedad_id': propiedad_id,
                'inquilino_id': inquilino_id,
                'fecha_inicio': fecha_inicio,
                'fecha_fin': fecha_fin,
                'precio_mensual': precio,
                'estado': 'activo',
            }
            resp = _enviar_a_api(request, "/contratos/", payload)
            if resp is not None and resp.status_code in (200, 201):
                datos = _json_api(resp)
                if datos:
                    _guardar_contrato_web(datos)
                messages.success(
                    request,
                    f'Contrato creado para la vivienda #{propiedad_id}.')
            else:
                messages.error(
                    request, f'No se pudo crear el contrato: '
                             f'{_detalle_error(resp)}')
            return redirect('usuarios:contratos')
        if accion == 'pdf':
            if not es_admin:
                messages.error(
                    request, 'Solo el administrador adjunta documentos.')
                return redirect('usuarios:contratos')
            cid = request.POST.get('contrato_id')
            visibles = {str(c.get('id')) for c in _contratos_visibles(request)}
            if not cid or str(cid) not in visibles:
                messages.error(request, 'Elegí un contrato válido.')
                return redirect('usuarios:contratos')
            documento = request.FILES.get('documento')
            if documento is None:
                messages.error(request, 'Elegí un archivo PDF para adjuntar.')
                return redirect('usuarios:contratos')
            error_pdf = _validar_pdf(documento)
            if error_pdf:
                messages.error(request, error_pdf)
                return redirect('usuarios:contratos')
            subido, ruta = _subir_pdf_api(request, cid, documento)
            if not subido:
                messages.error(
                    request, 'No se pudo subir el PDF al servidor.')
            elif not ruta:
                messages.success(
                    request, f'PDF adjuntado al contrato #{cid}.')
            else:
                resp = _enviar_a_api(
                    request, f"/contratos/{cid}", {'pdf_url': ruta},
                    method='PATCH')
                if resp is not None and resp.status_code == 200:
                    _guardar_contrato_web(
                        {'id': int(cid), 'pdf_url': _url_abs_api(ruta)})
                    messages.success(
                        request, f'PDF adjuntado al contrato #{cid}.')
                else:
                    messages.error(
                        request,
                        'El PDF se subió pero no se pudo asignar al contrato: '
                        f'{_detalle_error(resp)}')
        elif accion == 'estado':
            if not es_admin:
                messages.error(
                    request, 'Solo el administrador cierra contratos.')
                return redirect('usuarios:contratos')
            cid = request.POST.get('contrato_id')
            nuevo = request.POST.get('estado')
            resp = _enviar_a_api(
                request, f"/contratos/{cid}", {'estado': nuevo}, method='PATCH')
            if resp is not None and resp.status_code == 200:
                _guardar_contrato_web({'id': int(cid), 'estado': nuevo})
                extra = (' La vivienda quedó DISPONIBLE.'
                         if nuevo in ('finalizado', 'cancelado') else '')
                messages.success(
                    request, f'Contrato #{cid} marcado como {nuevo}.{extra}')
            else:
                messages.error(request, f"Error: {_detalle_error(resp)}")
        return redirect('usuarios:contratos')

    contratos = _contratos_visibles(request)
    propiedades = _propiedades_api(request)
    inq_map = _mapa_nombres(request) if es_admin else {}
    prop_map = {p.get('id'): p.get('direccion', '') for p in propiedades}
    prop_dueno = {p.get('id'): p.get('propietario_id') for p in propiedades}
    for c in contratos:
        c['propiedad_direccion'] = (
            prop_map.get(c.get('propiedad_id')) or c.get('propiedad_direccion', ''))
        c['inquilino_nombre'] = (
            inq_map.get(c.get('inquilino_id')) or c.get('inquilino_nombre', ''))
        c['puede_formato'] = (
            es_admin
            or c.get('inquilino_id') == request.user.pk
            or prop_dueno.get(c.get('propiedad_id')) == request.user.pk)
        if not c.get('pdf_url'):
            pdf = os.path.join(
                settings.MEDIA_ROOT, 'contratos', f'contrato_{c.get("id")}.pdf')
            if os.path.isfile(pdf):
                c['pdf_url'] = f'{settings.MEDIA_URL}contratos/contrato_{c.get("id")}.pdf'
    inquilinos = []
    if es_admin:
        inquilinos = [
            u for u in _usuarios_api(request)
            if (u.get('rol') or '').lower() == 'inquilino' and u.get('activo')
        ]
        inquilinos.sort(key=lambda u: (u.get('nombre') or '').lower())
    hoy = date.today()
    return render(request, 'usuarios/contratos.html', {
        'contratos': contratos,
        'es_admin': es_admin,
        'es_propietario': rol == 'propietario',
        'propiedades': propiedades if es_admin else [],
        'inquilinos': inquilinos,
        'hoy': hoy.isoformat(),
        'fin_sugerido': date(hoy.year + 1, hoy.month, hoy.day).isoformat(),
    })


def _meses_del_contrato(fecha_inicio, fecha_fin):
    """Todos los (año, mes) que abarca el plazo del contrato."""
    try:
        ini = date.fromisoformat(str(fecha_inicio)[:10])
        fin = date.fromisoformat(str(fecha_fin)[:10])
    except (TypeError, ValueError):
        return []
    meses, y, m = [], ini.year, ini.month
    while (y, m) <= (fin.year, fin.month):
        meses.append((y, m))
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return meses


def _meses_esperados(fecha_inicio, fecha_fin):
    """(año, mes) que un contrato debería tener pagados hasta hoy."""
    hoy = date.today()
    return [(y, m) for (y, m) in _meses_del_contrato(fecha_inicio, fecha_fin)
            if (y, m) <= (hoy.year, hoy.month)]


def _mes_iso(y, m):
    return f'{y:04d}-{m:02d}'


def _fecha_ar(valor):
    """Fecha ISO (YYYY-MM-DD...) a DD/MM/AAAA para documentos."""
    try:
        return date.fromisoformat(str(valor)[:10]).strftime('%d/%m/%Y')
    except (TypeError, ValueError):
        return str(valor or '')


def _meses_cubiertos_por_pago(pago, precio=0):
    """Meses que cubre un pago.

    La API del servidor no guarda `meses_cubiertos`: se deduce del monto
    (monto / precio del contrato).
    """
    try:
        if pago.get('meses_cubiertos'):
            return max(1, min(int(pago['meses_cubiertos']), 12))
    except (TypeError, ValueError):
        pass
    try:
        monto = float(pago.get('monto') or 0)
    except (TypeError, ValueError):
        monto = 0
    if precio > 0 and monto > 0:
        return max(1, min(int(round(monto / precio)), 12))
    return 1


def _resumen_pagos(contrato, pagos, contar_cerrados=False):
    """Cobrado, pagado y pendiente de un contrato.

    Un contrato finalizado o cancelado deja de generar meses pendientes; con
    `contar_cerrados=True` se calcula igual (formato de cancelación, donde
    interesa mostrar la liquidación al momento de la rescisión).
    """
    precio = float(contrato.get('precio_mensual') or 0)
    vigente = contrato.get('estado') == 'activo'
    plazo = _meses_del_contrato(contrato.get(
        'fecha_inicio'), contrato.get('fecha_fin'))
    cubiertos = set()
    for pago in sorted(pagos, key=lambda p: str(p.get('fecha_pago') or '')):
        # Cada pago cubre primero el mes más viejo que siga impago.
        arranque = next((mes for mes in plazo
                         if _mes_iso(*mes) not in cubiertos), None)
        if arranque is None:
            mes = str(pago.get('fecha_pago') or '')[:7]
            try:
                arranque = (int(mes[:4]), int(mes[5:7]))
            except ValueError:
                continue
        y, m = arranque
        for _ in range(_meses_cubiertos_por_pago(pago, precio)):
            cubiertos.add(_mes_iso(y, m))
            m += 1
            if m == 13:
                y, m = y + 1, 1
    esperados = _meses_esperados(contrato.get(
        'fecha_inicio'), contrato.get('fecha_fin'))
    pagados = [mes for mes in esperados if _mes_iso(*mes) in cubiertos]
    if vigente or contar_cerrados:
        pendientes = [_mes_iso(y, m) for (y, m) in esperados
                      if _mes_iso(y, m) not in cubiertos]
    else:
        pendientes = []
    return {
        'id': contrato.get('id'),
        'propiedad': contrato.get('propiedad_direccion') or contrato.get('propiedad_id'),
        'inquilino': contrato.get('inquilino_nombre') or contrato.get('inquilino_id'),
        'estado': contrato.get('estado'),
        'cerrado': not vigente,
        'precio': precio,
        'meses_esperados': len(esperados),
        'meses_pagados': len(pagados),
        'pendientes': pendientes,
        'cobrado': sum(float(p.get('monto') or 0) for p in pagos),
        'saldo': precio * len(pendientes),
    }


@login_required
@sesion_api_vigente
@rol_requerido('administrador', 'propietario', 'inquilino')
def formato_cancelacion_contrato(request, pk):
    """Formato imprimible para rescindir el contrato y firmarlo."""
    contrato = next((c for c in _contratos_visibles(request)
                     if str(c.get('id')) == str(pk)), None)
    if contrato is None:
        raise Http404('Contrato inexistente o fuera de tu alcance.')

    propiedad = next((p for p in _propiedades_api(request)
                      if str(p.get('id')) == str(contrato.get('propiedad_id'))),
                     None)
    puede_formato = (
        getattr(request.user, 'rol', None) == 'administrador'
        or contrato.get('inquilino_id') == request.user.pk
        or (propiedad or {}).get('propietario_id') == request.user.pk)
    if not puede_formato:
        raise Http404('No tenés permiso para este contrato.')

    usuarios = _usuarios_api(request)
    inquilino = next((u for u in usuarios
                      if str(u.get('id')) == str(contrato.get('inquilino_id'))),
                     None)
    propietario_id = (propiedad or {}).get('propietario_id')
    propietario = (next((u for u in usuarios
                         if str(u.get('id')) == str(propietario_id)), None)
                   if propietario_id else None)

    pagos = _obtener_de_api(request, f"/pagos/contrato/{pk}") or []
    resumen = _resumen_pagos(
        dict(contrato,
             propiedad_direccion=(propiedad or {}).get('direccion', ''),
             inquilino_nombre=(inquilino or {}).get('nombre', '')), pagos,
        contar_cerrados=True)

    return render(request, 'usuarios/contrato_cancelacion.html', {
        'contrato': contrato,
        'propiedad': propiedad,
        'inquilino': inquilino,
        'propietario': propietario,
        'resumen': resumen,
        'inicio': _fecha_ar(contrato.get('fecha_inicio')),
        'fin': _fecha_ar(contrato.get('fecha_fin')),
        'hoy': date.today().strftime('%d/%m/%Y'),
    })


def _json_body(request):
    try:
        return json.loads(request.body or b'{}')
    except (TypeError, ValueError):
        return {}


def _contrato_para_pago(request, contrato_id):
    """Contrato propio del inquilino, activo y con precio usable."""
    for contrato in _contratos_visibles(request):
        if str(contrato.get('id')) != str(contrato_id):
            continue
        if contrato.get('estado') != 'activo':
            raise ValueError('El contrato ya no está activo.')
        precio = float(contrato.get('precio_mensual') or 0)
        if precio <= 0:
            raise ValueError('El contrato no tiene un precio válido.')
        pagos = _obtener_de_api(request, f"/pagos/contrato/{contrato_id}") or []
        pendientes = _resumen_pagos(contrato, pagos)['pendientes']
        return contrato, precio, pendientes
    raise ValueError('Ese contrato no te pertenece.')


def _contrato_api_equivalente(request, contrato_id):
    """Contrato de la API con los mismos datos que la copia local.

    Si el servidor reinició su base (o el admin borró el original), el id
    que tiene el aviso de pago ya no existe. Se busca por vivienda,
    inquilino y fechas para poder registrar el pago sin perderlo.
    """
    espejo = ContratoWeb.objects.filter(api_id=contrato_id).first()
    if espejo is None:
        return None
    for contrato in (_obtener_de_api(request, "/contratos/") or []):
        if (contrato.get('propiedad_id') == espejo.propiedad_id
                and contrato.get('inquilino_id') == espejo.inquilino_id
                and str(contrato.get('fecha_inicio'))[:10]
                == espejo.fecha_inicio.isoformat()
                and str(contrato.get('fecha_fin'))[:10]
                == espejo.fecha_fin.isoformat()):
            return contrato
    return None


def _referencia_paypal(contrato_id, meses, inquilino_id):
    return f'{contrato_id}:{meses}:{inquilino_id}'


def _referencia_de_orden(orden):
    unidades = orden.get('purchase_units') or []
    if not unidades:
        return None
    referencia = str(unidades[0].get('custom_id') or '')
    partes = referencia.split(':')
    if len(partes) != 3:
        return None
    try:
        return int(partes[0]), int(partes[1]), int(partes[2])
    except ValueError:
        return None


def _captura_completada(orden, monto_esperado):
    """Devuelve la captura si PayPal confirmó el monto y la moneda."""
    if str(orden.get('status') or '').upper() != 'COMPLETED':
        return None
    unidades = orden.get('purchase_units') or []
    if not unidades:
        return None
    capturas = (unidades[0].get('payments') or {}).get('captures') or []
    if not capturas:
        return None
    captura = capturas[0]
    if str(captura.get('status') or '').upper() != 'COMPLETED':
        return None
    importe = captura.get('amount') or {}
    if str(importe.get('currency_code') or '').upper() != paypal_api.moneda():
        return None
    try:
        if abs(float(importe.get('value')) - float(monto_esperado)) > 0.01:
            return None
    except (TypeError, ValueError):
        return None
    return captura


def _mensaje_pendiente(pendiente):
    if pendiente.estado == PagoPendiente.Estado.APROBADO:
        return 'Ese pago ya fue aprobado por el administrador.'
    if pendiente.estado == PagoPendiente.Estado.RECHAZADO:
        return 'Ese pago fue rechazado. Consultá con el administrador.'
    return 'El pago ya está registrado y espera la aprobación del administrador.'


@login_required
@rol_requerido('inquilino')
@require_POST
def paypal_crear_orden_view(request):
    """Crea una orden de PayPal por los meses elegidos por el inquilino."""
    if not paypal_api.configurado():
        return JsonResponse(
            {'error': 'PayPal no está configurado en el servidor. '
                      'El administrador debe cargar las credenciales sandbox.'},
            status=503)
    datos = request.POST or _json_body(request)
    try:
        contrato_id = int(datos.get('contrato_id') or 0)
        meses = int(datos.get('meses_cubiertos') or 1)
    except (TypeError, ValueError):
        return JsonResponse({'error': 'Los datos del pago no son válidos.'},
                            status=400)
    meses = max(1, min(meses, 12))
    try:
        _, precio, pendientes = _contrato_para_pago(request, contrato_id)
    except TokenExpirado:
        return JsonResponse(
            {'error': 'Tu sesión expiró. Ingresá de nuevo.'}, status=401)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)
    if not pendientes:
        return JsonResponse(
            {'error': 'No hay meses pendientes en ese contrato.'}, status=400)
    meses = min(meses, 12, len(pendientes))
    monto = round(precio * meses, 2)
    try:
        orden = paypal_api.crear_orden(
            monto,
            f'Alquiler contrato #{contrato_id} · {meses} mes(es)',
            _referencia_paypal(contrato_id, meses, request.user.pk))
    except requests.RequestException as exc:
        return JsonResponse({'error': paypal_api.error_legible(exc)},
                            status=502)
    return JsonResponse({
        'id': orden.get('id'),
        'monto': monto,
        'moneda': paypal_api.moneda(),
    })


@login_required
@rol_requerido('inquilino')
@require_POST
def paypal_capturar_pago_view(request):
    """Captura la orden aprobada en PayPal y la deja pendiente de revisión."""
    if not paypal_api.configurado():
        return JsonResponse(
            {'error': 'PayPal no está configurado en el servidor.'}, status=503)
    datos = request.POST or _json_body(request)
    orden_id = str(datos.get('orderID') or '').strip()
    if not orden_id:
        return JsonResponse({'error': 'Falta la orden de PayPal.'}, status=400)

    existente = PagoPendiente.objects.filter(paypal_order_id=orden_id).first()
    if existente:
        if existente.inquilino_id != request.user.pk:
            return JsonResponse({'error': 'Esa orden no te pertenece.'},
                                status=403)
        return JsonResponse({'ok': True, 'estado': existente.estado,
                             'mensaje': _mensaje_pendiente(existente)})

    try:
        orden = paypal_api.obtener_orden(orden_id)
        referencia = _referencia_de_orden(orden)
        if referencia is None:
            return JsonResponse(
                {'error': 'La orden no corresponde a un alquiler.'}, status=400)
        contrato_id, meses, inquilino_id = referencia
        if not 1 <= meses <= 12:
            return JsonResponse(
                {'error': 'La orden tiene una cantidad de meses inválida.'},
                status=400)
        if inquilino_id != request.user.pk:
            return JsonResponse({'error': 'Esa orden no te pertenece.'},
                                status=403)
        _, precio, _ = _contrato_para_pago(request, contrato_id)
        monto = round(precio * meses, 2)
        orden = paypal_api.capturar_orden(orden_id)
        if _captura_completada(orden, monto) is None:
            return JsonResponse(
                {'error': 'PayPal no confirmó el pago con el monto esperado.'},
                status=400)
    except TokenExpirado:
        return JsonResponse(
            {'error': 'Tu sesión expiró. Ingresá de nuevo.'}, status=401)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)
    except requests.RequestException as exc:
        return JsonResponse({'error': paypal_api.error_legible(exc)},
                            status=502)

    pendiente, creado = PagoPendiente.objects.get_or_create(
        paypal_order_id=orden_id,
        defaults={
            'contrato_id': contrato_id,
            'inquilino_id': request.user.pk,
            'monto': monto,
            'meses_cubiertos': meses,
            'fecha_pago': date.today(),
            'metodo': PagoPendiente.Metodo.TARJETA,
            'descripcion': f'PayPal · orden {orden_id}',
        })
    return JsonResponse({
        'ok': True,
        'estado': pendiente.estado,
        'creado': creado,
        'mensaje': ('Pago recibido. Queda pendiente de aprobación del '
                    'administrador.' if creado else _mensaje_pendiente(pendiente)),
    })


@login_required
@rol_requerido('inquilino')
@require_POST
def pago_efectivo_view(request):
    """Aviso de pago en efectivo: queda pendiente de confirmación del admin."""
    datos = request.POST or _json_body(request)
    try:
        contrato_id = int(datos.get('contrato_id') or 0)
        meses = int(datos.get('meses_cubiertos') or 1)
    except (TypeError, ValueError):
        messages.error(request, 'Los datos del pago no son válidos.')
        return redirect('usuarios:pagos')
    try:
        _, precio, pendientes = _contrato_para_pago(request, contrato_id)
    except TokenExpirado:
        raise
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect('usuarios:pagos')
    if not pendientes:
        messages.error(
            request, 'No hay meses pendientes en ese contrato.')
        return redirect(f"{reverse('usuarios:pagos')}?contrato={contrato_id}")

    meses = max(1, min(meses, 12, len(pendientes)))
    ya_avisado = PagoPendiente.objects.filter(
        contrato_id=contrato_id,
        inquilino_id=request.user.pk,
        metodo=PagoPendiente.Metodo.EFECTIVO,
        estado=PagoPendiente.Estado.PENDIENTE).exists()
    if ya_avisado:
        messages.warning(
            request, 'Ya avisaste un pago en efectivo para este contrato. '
                     'Esperá la confirmación del administrador.')
    else:
        PagoPendiente.objects.create(
            contrato_id=contrato_id,
            inquilino_id=request.user.pk,
            monto=round(precio * meses, 2),
            meses_cubiertos=meses,
            fecha_pago=date.today(),
            metodo=PagoPendiente.Metodo.EFECTIVO,
            descripcion='Efectivo · aviso del inquilino')
        messages.success(
            request, 'Aviso de pago en efectivo registrado. El administrador '
                     'lo confirmará cuando reciba el dinero.')
    return redirect(f"{reverse('usuarios:pagos')}?contrato={contrato_id}")


def _opciones_meses(cantidad_maxima):
    return [
        {'valor': n, 'texto': '1 mes' if n == 1 else f'{n} meses'}
        for n in range(1, cantidad_maxima + 1)
    ]


@login_required
@sesion_api_vigente
@rol_requerido('administrador', 'propietario', 'inquilino')
def modulo_pagos(request):
    rol = getattr(request.user, 'rol', None)
    es_admin = rol == 'administrador'
    contratos = _contratos_visibles(request)
    contrato_id = request.GET.get('contrato') or request.POST.get('contrato_id')
    ids_visibles = {str(c.get('id')) for c in contratos}
    if contrato_id and str(contrato_id) not in ids_visibles:
        messages.error(
            request, 'Ese contrato no está entre los que podés consultar.')
        return redirect('usuarios:pagos')

    if request.method == 'POST':
        accion = request.POST.get('accion')
        if accion == 'cancelar-aviso':
            if rol != 'inquilino':
                messages.error(
                    request, 'Solo el inquilino cancela sus propios avisos.')
                return redirect('usuarios:pagos')
            pendiente = PagoPendiente.objects.filter(
                pk=request.POST.get('pendiente_id'),
                inquilino_id=request.user.pk,
                estado=PagoPendiente.Estado.PENDIENTE).first()
            if pendiente is None:
                messages.error(
                    request, 'Ese aviso de pago ya no se puede cancelar.')
                return redirect('usuarios:pagos')
            pendiente.estado = PagoPendiente.Estado.RECHAZADO
            pendiente.revisado_por = request.user.username
            pendiente.revisado = timezone.now()
            pendiente.save(update_fields=[
                'estado', 'revisado_por', 'revisado'])
            messages.success(
                request,
                'Aviso de pago cancelado: no se descuentan meses.')
            return redirect(f"{request.path}?contrato={pendiente.contrato_id}")
        if accion in ('aprobar-pago', 'rechazar-pago'):
            if not es_admin:
                messages.error(
                    request, 'Solo el administrador revisa pagos online.')
                return redirect('usuarios:pagos')
            try:
                pendiente = PagoPendiente.objects.get(
                    pk=request.POST.get('pendiente_id'),
                    estado=PagoPendiente.Estado.PENDIENTE)
            except (PagoPendiente.DoesNotExist, TypeError, ValueError):
                messages.error(
                    request, 'Ese pago pendiente ya no está disponible.')
                return redirect('usuarios:pagos')

            if accion == 'rechazar-pago':
                pendiente.estado = PagoPendiente.Estado.RECHAZADO
                pendiente.revisado_por = request.user.username
                pendiente.revisado = timezone.now()
                pendiente.save(update_fields=[
                    'estado', 'revisado_por', 'revisado'])
                messages.success(
                    request, 'Pago cancelado. Los meses no se descontaron.')
                return redirect(f"{request.path}?contrato={pendiente.contrato_id}")

            payload = {
                'fecha_pago': f'{pendiente.fecha_pago.isoformat()}T00:00:00',
                'monto': float(pendiente.monto),
                'metodo_pago': pendiente.metodo,
                'descripcion': pendiente.descripcion,
                'usuario_id': pendiente.inquilino_id,
                'contrato_id': pendiente.contrato_id,
            }
            if pendiente.paypal_order_id:
                payload['paypal_transaction_id'] = pendiente.paypal_order_id[:100]
            resp = _enviar_a_api(request, "/pagos/", payload)
            anterior = pendiente.contrato_id
            if resp is not None and resp.status_code == 404:
                # El servidor cambió el id del contrato (o reinició su base);
                # se busca el equivalente y se reintenta una sola vez.
                equivalente = _contrato_api_equivalente(request, anterior)
                if (equivalente and equivalente.get('id')
                        and equivalente['id'] != anterior):
                    pendiente.contrato_id = equivalente['id']
                    pendiente.save(update_fields=['contrato_id'])
                    ContratoWeb.objects.filter(api_id=anterior).delete()
                    _guardar_contrato_web(equivalente)
                    payload['contrato_id'] = equivalente['id']
                    resp = _enviar_a_api(request, "/pagos/", payload)
            if resp is not None and resp.status_code == 201:
                try:
                    pago_id = resp.json().get('id')
                except ValueError:
                    pago_id = None
                pendiente.estado = PagoPendiente.Estado.APROBADO
                pendiente.pago_id = pago_id
                pendiente.revisado_por = request.user.username
                pendiente.revisado = timezone.now()
                pendiente.save(update_fields=[
                    'estado', 'pago_id', 'revisado_por', 'revisado',
                    'contrato_id'])
                mensaje = (f'Pago aprobado y registrado en el contrato '
                           f'#{pendiente.contrato_id}.')
                if pendiente.contrato_id != anterior:
                    mensaje += (f' El servidor había cambiado el id del '
                                f'contrato (antes #{anterior}).')
                messages.success(request, mensaje)
            elif resp is not None and resp.status_code == 404:
                messages.error(
                    request,
                    f'El servidor no tiene el contrato '
                    f'#{pendiente.contrato_id}: puede haberse eliminado o su '
                    'base se reinició. El aviso sigue pendiente; recreá el '
                    'contrato y volvé a aprobarlo.')
            else:
                messages.error(
                    request,
                    f'No se pudo registrar el pago: {_detalle_error(resp)}')
            visibles = {str(c.get('id')) for c in _contratos_visibles(request)}
            if str(pendiente.contrato_id) in visibles:
                return redirect(
                    f"{request.path}?contrato={pendiente.contrato_id}")
            return redirect('usuarios:pagos')

        if not es_admin:
            messages.error(
                request, 'Solo el administrador registra pagos.')
            return redirect('usuarios:pagos')
        contrato = next((c for c in contratos
                         if str(c.get('id')) == str(contrato_id)), None)
        if contrato is None:
            messages.error(
                request, 'Elegí un contrato para registrar el pago.')
            return redirect('usuarios:pagos')
        if not contrato.get('inquilino_id'):
            messages.error(request, 'El contrato no tiene inquilino asignado.')
            return redirect(f"{request.path}?contrato={contrato_id}")
        fecha = (request.POST.get('fecha_pago') or '').strip()
        if len(fecha) == 10:
            fecha = f'{fecha}T00:00:00'
        try:
            monto = float(request.POST.get('monto') or 0)
        except (TypeError, ValueError):
            monto = 0
        if monto <= 0:
            messages.error(request, 'El monto del pago debe ser mayor a cero.')
            return redirect(f"{request.path}?contrato={contrato_id}")
        payload = {
            'fecha_pago': fecha,
            'monto': monto,
            'metodo_pago': request.POST.get('metodo_pago'),
            'descripcion': (request.POST.get('descripcion') or '').strip() or None,
            'usuario_id': contrato.get('inquilino_id'),
            'contrato_id': contrato.get('id'),
        }
        resp = _enviar_a_api(request, "/pagos/", payload)
        if resp is not None and resp.status_code == 201:
            messages.success(request, "Pago registrado.")
        else:
            messages.error(request, f"Error: {_detalle_error(resp)}")
        return redirect(f"{request.path}?contrato={contrato_id}")

    props = {p.get('id'): p.get('direccion', '')
             for p in _propiedades_api(request)}
    inqs = {u.get('id'): u.get('nombre', '') for u in _usuarios_api(request)}
    for c in contratos:
        c['propiedad_direccion'] = props.get(c.get('propiedad_id'), '')
        c['inquilino_nombre'] = inqs.get(c.get('inquilino_id'), '')

    resumen = []
    for c in contratos:
        resumen.append(_resumen_pagos(c, _obtener_de_api(
            request, f"/pagos/contrato/{c['id']}") or []))

    pagos = []
    actual = None
    if contrato_id:
        pagos = _obtener_de_api(
            request, f"/pagos/contrato/{contrato_id}") or []
        actual = next((r for r in resumen if str(r['id']) == str(contrato_id)), None)
        precio_actual = float((actual or {}).get('precio') or 0)
        for pago in pagos:
            pago['meses_cubiertos'] = _meses_cubiertos_por_pago(
                pago, precio_actual)

    pendientes_pago = []
    if es_admin:
        contrato_prop = {c.get('id'): props.get(c.get('propiedad_id'), '')
                         for c in contratos}
        pendientes_pago = list(PagoPendiente.objects.filter(
            estado=PagoPendiente.Estado.PENDIENTE))
        for pendiente in pendientes_pago:
            pendiente.propiedad_nombre = contrato_prop.get(
                pendiente.contrato_id, '')
            pendiente.inquilino_nombre = inqs.get(pendiente.inquilino_id, '')

    mis_pendientes = []
    if rol == 'inquilino':
        mis_pendientes = list(PagoPendiente.objects.filter(
            inquilino_id=request.user.pk,
            contrato_id=contrato_id or 0).order_by('-creado')[:10])

    pendientes_actual = actual['pendientes'] if actual else []
    return render(request, 'usuarios/pagos.html', {
        'contratos': contratos,
        'resumen': resumen,
        'pagos': pagos,
        'contrato_actual': contrato_id,
        'actual': actual,
        'total_pendiente': sum(r['saldo'] for r in resumen),
        'es_admin': es_admin,
        'es_propietario': rol == 'propietario',
        'pendientes_pago': pendientes_pago,
        'mis_pendientes': mis_pendientes,
        'paypal_configurado': paypal_api.configurado(),
        'paypal_client_id': paypal_api.client_id(),
        'paypal_moneda': paypal_api.moneda(),
        'opciones_meses_online': _opciones_meses(
            max(1, min(12, len(pendientes_actual)))),
        'opciones_meses_admin': _opciones_meses(12),
    })


def _normalizar_solicitud_mantenimiento(solicitud, prop_map, inquilino_nombre=''):
    """Fila de la API lista para el template (la API no manda 'titulo')."""
    descripcion = (solicitud.get('descripcion') or '').strip()
    estado = (solicitud.get('estado') or '').lower()
    return {
        'id': solicitud.get('id'),
        'api_id': solicitud.get('id'),
        'titulo': descripcion.split('\n', 1)[0][:80],
        'descripcion': descripcion,
        'estado': estado,
        'estado_label': {
            'pendiente': 'Pendiente',
            'en_proceso': 'En proceso',
            'resuelto': 'Resuelto',
            'rechazado': 'Rechazado',
            'cancelado': 'Cancelado',
        }.get(estado, estado),
        'propiedad_id': solicitud.get('propiedad_id'),
        'propiedad_direccion': prop_map.get(solicitud.get('propiedad_id'), ''),
        'inquilino_id': solicitud.get('inquilino_id'),
        'inquilino_nombre': inquilino_nombre,
        'created_at': (solicitud.get('created_at') or '')[:10],
    }


def _solicitud_web_dict(solicitud, prop_map):
    """Fila de la copia local con la forma que usa la plantilla."""
    estado = (solicitud.estado or '').lower()
    return {
        'id': solicitud.pk,
        'api_id': solicitud.api_id,
        'titulo': solicitud.titulo,
        'descripcion': solicitud.descripcion,
        'estado': estado,
        'estado_label': {
            'pendiente': 'Pendiente',
            'en_proceso': 'En proceso',
            'resuelto': 'Resuelto',
            'rechazado': 'Rechazado',
            'cancelado': 'Cancelado',
        }.get(estado, estado),
        'propiedad_id': solicitud.propiedad_id,
        'propiedad_direccion': (solicitud.propiedad_direccion
                                or prop_map.get(solicitud.propiedad_id, '')),
        'inquilino_id': solicitud.inquilino_id,
        'inquilino_nombre': solicitud.inquilino_nombre,
        'created_at': solicitud.creada.strftime('%Y-%m-%d'),
        'local': True,
    }


@login_required
@sesion_api_vigente
@rol_requerido('administrador', 'propietario', 'inquilino')
def modulo_mantenimiento(request):
    rol = getattr(request.user, 'rol', None)
    es_admin = rol == 'administrador'
    es_inquilino = rol == 'inquilino'

    if request.method == 'POST':
        accion = request.POST.get('accion')

        if accion in ('editar', 'reparar'):
            if rol not in ('administrador', 'propietario'):
                messages.error(
                    request,
                    'Solo el administrador o el propietario modifican una '
                    'vivienda en mantenimiento.')
                return redirect('usuarios:mantenimiento')
            try:
                pid = int(request.POST.get('propiedad_id') or 0)
            except (TypeError, ValueError):
                pid = 0
            vivienda = next(
                (p for p in _propiedades_api(request)
                 if p.get('id') == pid), None)
            if vivienda is None:
                messages.error(request, 'Esa vivienda no está a tu cargo.')
            elif (vivienda.get('estado') or '').upper() != 'MANTENIMIENTO':
                messages.error(
                    request, 'Esa vivienda no está en mantenimiento.')
            else:
                nuevo_estado = ('DISPONIBLE' if accion == 'reparar'
                                else 'MANTENIMIENTO')
                direccion = (request.POST.get('direccion')
                             if 'direccion' in request.POST
                             else vivienda.get('direccion') or '').strip()
                descripcion = (request.POST.get('descripcion')
                               if 'descripcion' in request.POST
                               else vivienda.get('descripcion') or '').strip()
                try:
                    precio = float(
                        request.POST.get('precio_mensual')
                        if 'precio_mensual' in request.POST
                        else vivienda.get('precio_mensual') or 0)
                except (TypeError, ValueError):
                    precio = -1
                if not direccion:
                    messages.error(request, 'La dirección no puede quedar vacía.')
                elif precio < 0:
                    messages.error(request, 'El precio mensual no es válido.')
                elif (nuevo_estado == 'DISPONIBLE'
                      and _contrato_activo_de(request, pid)):
                    messages.error(
                        request,
                        f'La vivienda #{pid} tiene un contrato activo: '
                        'finalizalo en Contratos antes de repararla.')
                else:
                    datos = _datos_vivienda_con_estado(vivienda, nuevo_estado)
                    datos.update({
                        'direccion': direccion[:255],
                        'descripcion': descripcion[:1000],
                        'precio_mensual': precio,
                    })
                    resp = _enviar_multipart_api(
                        request, f"/propiedades/{pid}", datos, method='PUT')
                    if resp is not None and resp.status_code == 200:
                        _quitar_estado_local(pid)
                        if accion == 'reparar':
                            messages.success(
                                request,
                                f'Vivienda #{pid} reparada: ahora está '
                                'DISPONIBLE.')
                        else:
                            messages.success(
                                request,
                                f'Cambios de la vivienda #{pid} guardados.')
                    elif resp is None or resp.status_code >= 500:
                        _guardar_estado_local(pid, nuevo_estado, {
                            'direccion': direccion[:255],
                            'descripcion': descripcion[:1000],
                            'precio_mensual': precio,
                        })
                        if accion == 'reparar':
                            messages.warning(
                                request,
                                f'El servidor no respondió '
                                f'({_detalle_error(resp)}); la vivienda #{pid} '
                                'quedó marcada como DISPONIBLE en esta web.')
                        else:
                            messages.warning(
                                request,
                                f'El servidor no respondió '
                                f'({_detalle_error(resp)}); los cambios de la '
                                f'vivienda #{pid} quedaron guardados en esta '
                                'web.')
                    else:
                        messages.error(
                            request, f"Error: {_detalle_error(resp)}")
            return redirect('usuarios:mantenimiento')

        if es_inquilino and accion == 'crear':
            titulo = (request.POST.get('titulo') or '').strip()
            descripcion = (request.POST.get('descripcion') or '').strip()
            try:
                propiedad_id = int(request.POST.get('propiedad_id') or 0)
            except (TypeError, ValueError):
                propiedad_id = 0
            if len(titulo) < 3 or len(descripcion) < 10 or propiedad_id <= 0:
                messages.error(
                    request,
                    'Completá un título (mínimo 3) y una descripción '
                    '(mínimo 10) para el problema.')
                return redirect('usuarios:mantenimiento')
            # La API no guarda 'titulo': se conserva como primera línea.
            payload = {
                'descripcion': f'{titulo[:200]}\n{descripcion}'[:1000],
                'propiedad_id': propiedad_id,
                'inquilino_id': request.user.pk,
            }
            resp = _enviar_a_api(request, "/mantenimiento/", payload)
            creada_en_api = resp is not None and resp.status_code == 201
            fallo_servidor = resp is None or resp.status_code >= 500
            datos = (_json_api(resp) or {}) if creada_en_api else {}
            direccion = ''
            for p in _propiedades_api(request):
                if p.get('id') == propiedad_id:
                    direccion = p.get('direccion', '')
                    break
            if creada_en_api or fallo_servidor:
                # El servidor tiene roto el listado de mantenimiento (500);
                # si el alta falla igual guardamos la copia local para que la
                # solicitud no se pierda y aparezca en la lista.
                SolicitudMantenimientoWeb.objects.create(
                    api_id=datos.get('id'),
                    titulo=titulo[:200],
                    descripcion=descripcion[:1000],
                    estado=(datos.get('estado') or 'PENDIENTE').upper()[:20],
                    propiedad_id=propiedad_id,
                    propiedad_direccion=direccion[:255],
                    inquilino_id=request.user.pk,
                    inquilino_nombre=request.user.username[:150],
                )
            if creada_en_api:
                messages.success(
                    request, 'Solicitud de mantenimiento enviada.')
            elif fallo_servidor:
                messages.warning(
                    request,
                    'El servidor no pudo registrar la solicitud '
                    f'({_detalle_error(resp)}) pero quedó guardada en esta '
                    'web y ya aparece en la lista.')
            else:
                messages.error(request, f"Error: {_detalle_error(resp)}")
            return redirect('usuarios:mantenimiento')

        if accion == 'cambiar_estado':
            if rol not in ('administrador', 'propietario'):
                messages.error(
                    request,
                    'Solo el administrador o el propietario modifican las '
                    'solicitudes de mantenimiento.')
                return redirect('usuarios:mantenimiento')
            sol_id = request.POST.get('solicitud_id')
            api_id = request.POST.get('api_id')
            estado = (request.POST.get('estado') or '').strip().upper()
            if estado not in ('PENDIENTE', 'EN_PROCESO', 'RESUELTO',
                              'RECHAZADO'):
                messages.error(request, 'Estado inválido.')
                return redirect('usuarios:mantenimiento')
            descripcion = (request.POST.get('descripcion') or '').strip()
            if len(descripcion) < 10:
                messages.error(
                    request,
                    'La descripción debe tener al menos 10 caracteres.')
                return redirect('usuarios:mantenimiento')
            descripcion = descripcion[:1000]
            titulo = descripcion.split('\n', 1)[0][:200]
            try:
                propiedad_id = int(request.POST.get('propiedad_id') or 0)
            except (TypeError, ValueError):
                propiedad_id = 0
            if rol == 'propietario':
                propias = {p.get('id') for p in _propiedades_api(request)}
                if propiedad_id not in propias:
                    messages.error(
                        request,
                        'Esa solicitud no pertenece a tus viviendas.')
                    return redirect('usuarios:mantenimiento')
            propiedad_direccion = (
                request.POST.get('propiedad_direccion') or '')[:255]
            try:
                inquilino_id = int(request.POST.get('inquilino_id') or 0)
            except (TypeError, ValueError):
                inquilino_id = 0
            inquilino_nombre = (
                request.POST.get('inquilino_nombre') or '')[:150]

            def guardar_copia_web():
                copia = None
                if api_id:
                    copia = SolicitudMantenimientoWeb.objects.filter(
                        api_id=api_id).first()
                elif sol_id:
                    try:
                        copia = SolicitudMantenimientoWeb.objects.filter(
                            pk=int(sol_id)).first()
                    except (TypeError, ValueError):
                        copia = None
                if copia is None:
                    copia = SolicitudMantenimientoWeb(
                        api_id=int(api_id) if api_id else None)
                copia.titulo = titulo
                copia.descripcion = descripcion
                copia.estado = estado
                copia.propiedad_id = propiedad_id
                copia.propiedad_direccion = propiedad_direccion
                copia.inquilino_id = inquilino_id
                copia.inquilino_nombre = inquilino_nombre
                copia.save()
                return copia

            if api_id:
                resp = _enviar_a_api(
                    request, f"/mantenimiento/{api_id}",
                    {'estado': estado, 'descripcion': descripcion},
                    method='PATCH')
                if resp is not None and resp.status_code == 200:
                    SolicitudMantenimientoWeb.objects.filter(
                        api_id=api_id).update(
                            estado=estado, descripcion=descripcion,
                            titulo=titulo)
                    messages.success(request, "Solicitud actualizada.")
                elif resp is None or resp.status_code >= 500:
                    # El servidor tiene roto el mantenimiento: los cambios se
                    # guardan igual en la copia local de la web.
                    guardar_copia_web()
                    messages.warning(
                        request,
                        'El servidor no respondió '
                        f'({_detalle_error(resp)}); los cambios quedaron '
                        'guardados en esta web.')
                else:
                    messages.error(request, f"Error: {_detalle_error(resp)}")
            else:
                try:
                    local = SolicitudMantenimientoWeb.objects.filter(
                        pk=int(sol_id)).first()
                except (TypeError, ValueError):
                    local = None
                if local is None:
                    messages.error(
                        request, 'No se encontró la solicitud de mantenimiento.')
                else:
                    local.titulo = titulo
                    local.descripcion = descripcion
                    local.estado = estado
                    local.save(update_fields=[
                        'titulo', 'descripcion', 'estado'])
                    messages.success(request, "Solicitud actualizada.")
            return redirect('usuarios:mantenimiento')

        return redirect('usuarios:mantenimiento')

    # Los modelos espejo (managed=False) apuntan a tablas de MySQL; esta copia
    # usa SQLite, así que todo se arma con lo que responde la API.
    props = _propiedades_api(request)
    prop_map = {p.get('id'): p.get('direccion', '') for p in props
                if isinstance(p, dict)}
    propiedades_activas = []
    lista_no_disponible = False

    datos = _obtener_de_api(request, "/mantenimiento/")
    lista_no_disponible = datos is None
    solicitudes_api = datos if isinstance(datos, list) else []
    if es_inquilino:
        solicitudes_api = [
            s for s in solicitudes_api
            if s.get('inquilino_id') == request.user.pk
        ]
    elif rol == 'propietario':
        ids = set(prop_map)
        solicitudes_api = [
            s for s in solicitudes_api
            if s.get('propiedad_id') in ids
        ]

    inquilinos = {}
    if es_admin:
        inquilinos = {
            u.get('id'): u.get('nombre', '')
            for u in (_obtener_de_api(request, "/usuarios/") or [])
            if isinstance(u, dict)
        }

    solicitudes = []
    por_api_id = {}
    for s in solicitudes_api:
        fila = _normalizar_solicitud_mantenimiento(
            s, prop_map,
            inquilinos.get(s.get('inquilino_id'),
                           request.user.username if es_inquilino else ''))
        if es_admin and not fila['inquilino_nombre']:
            fila['inquilino_nombre'] = f"#{s.get('inquilino_id')}"
        solicitudes.append(fila)
        if fila['api_id'] is not None:
            por_api_id[fila['api_id']] = fila

    # Copia local: se muestran las creadas desde la web que la API todavía
    # no devuelve (su listado responde 500). Si la API sí devuelve una
    # solicitud pero la copia local tiene cambios que no confirmó, la copia
    # local reemplaza a la fila de la API.
    locales = SolicitudMantenimientoWeb.objects.all()
    if es_inquilino:
        locales = locales.filter(inquilino_id=request.user.pk)
    elif rol == 'propietario':
        locales = locales.filter(propiedad_id__in=list(prop_map))
    for local in locales:
        if local.api_id and local.api_id in por_api_id:
            fila_api = por_api_id[local.api_id]
            sin_cambios = (
                (local.estado or '').upper()
                == (fila_api.get('estado') or '').upper()
                and (local.descripcion or '').strip()
                == (fila_api.get('descripcion') or '').strip())
            if sin_cambios:
                continue
            fila = _solicitud_web_dict(local, prop_map)
            if not fila['inquilino_nombre']:
                fila['inquilino_nombre'] = fila_api.get('inquilino_nombre') or ''
            fila['created_at'] = fila_api.get('created_at') or fila['created_at']
            solicitudes[solicitudes.index(fila_api)] = fila
            continue
        if not local.api_id:
            # La copia se guardó sin id porque el alta falló; cuando la API
            # vuelva a listar, se adopta el id de la fila equivalente.
            gemela = next((
                s for s in solicitudes_api
                if s.get('inquilino_id') == local.inquilino_id
                and s.get('propiedad_id') == local.propiedad_id
                and (s.get('descripcion') or '').startswith(local.titulo)
            ), None)
            if gemela:
                local.api_id = gemela.get('id')
                local.save(update_fields=['api_id'])
                continue
        fila = _solicitud_web_dict(local, prop_map)
        if es_inquilino:
            fila['inquilino_nombre'] = request.user.username
        solicitudes.append(fila)

    solicitudes.sort(key=lambda s: s.get('created_at') or '', reverse=True)

    if es_inquilino:
        vistos = set()
        for p in props:
            pid = p.get('id')
            if pid in vistos:
                continue
            vistos.add(pid)
            propiedades_activas.append({
                'id': pid,
                'direccion': p.get('direccion') or f'Vivienda #{pid}',
            })

    viviendas_mantenimiento = []
    if rol in ('administrador', 'propietario'):
        viviendas_mantenimiento = [
            {
                'id': p.get('id'),
                'direccion': p.get('direccion') or f"Vivienda #{p.get('id')}",
                'descripcion': p.get('descripcion') or '',
                'precio_mensual': p.get('precio_mensual') or 0,
                'imagen_url': _url_abs_api(p.get('imagen_url')),
                'local': bool(p.get('estado_local') or p.get('datos_locales')),
            }
            for p in props
            if (p.get('estado') or '').upper() == 'MANTENIMIENTO'
        ]

    return render(request, 'usuarios/mantenimiento.html', {
        'solicitudes': solicitudes,
        'puede_gestionar': rol in ('administrador', 'propietario'),
        'es_inquilino': es_inquilino,
        'propiedades_activas': propiedades_activas,
        'lista_no_disponible': lista_no_disponible,
        'viviendas_mantenimiento': viviendas_mantenimiento,
        'puede_reparar': rol in ('administrador', 'propietario'),
    })


# ==============================================================================
# REPORTES Y GESTIÓN DE USUARIOS (panel del administrador)
# ==============================================================================

def _datos_reporte(request):
    props = _obtener_de_api(request, "/propiedades/") or []
    contratos = _obtener_de_api(request, "/contratos/") or []
    mans = _obtener_de_api(request, "/mantenimiento/") or []
    inqs = {u.get('id'): u.get('nombre', '') for u in _usuarios_api(request)}
    props_map = {p['id']: p['direccion'] for p in props}

    resumen = []
    por_mes = {}
    for c in contratos:
        pagos = _obtener_de_api(
            request, f"/pagos/contrato/{c['id']}") or []
        r = _resumen_pagos(c, pagos)
        r['propiedad'] = props_map.get(
            c.get('propiedad_id'), c.get('propiedad_id'))
        r['inquilino'] = inqs.get(c.get('inquilino_id'), c.get('inquilino_id'))
        r['inicio'] = str(c.get('fecha_inicio'))[:10]
        r['fin'] = str(c.get('fecha_fin'))[:10]
        resumen.append(r)
        for p in pagos:
            clave = str(p.get('fecha_pago'))[:7]
            fila = por_mes.setdefault(
                clave, {'mes': clave, 'total': 0.0, 'operaciones': 0})
            fila['total'] += float(p.get('monto') or 0)
            fila['operaciones'] += 1

    def por_estado(items, clave='estado'):
        cont = {}
        for i in items:
            cont[i.get(clave)] = cont.get(i.get(clave), 0) + 1
        return cont

    meses = sorted(por_mes.values(), key=lambda x: x['mes'], reverse=True)
    return {
        'props': props,
        'contratos': contratos,
        'mans': mans,
        'resumen': resumen,
        'por_mes': meses,
        'tope': max((f['total'] for f in meses), default=0) or 1,
        'estados_prop': por_estado(props),
        'estados_man': por_estado(mans),
    }


@login_required
@sesion_api_vigente
def reportes_view(request):
    if getattr(request.user, 'rol', None) != 'administrador':
        messages.error(
            request, 'Los reportes pertenecen al panel del administrador.')
        return redirect('usuarios:dashboard')

    datos = _datos_reporte(request)

    if request.GET.get('csv'):
        return _respuesta_csv(request.GET['csv'], datos)

    activos = [c for c in datos['contratos'] if c.get('estado') == 'activo']
    kpis = [
        {'num': len(datos['props']), 'label': 'Viviendas',
         'icon': 'fa-house-chimney', 'bg': 'bg-blue', 'url': '/propiedades/'},
        {'num': datos['estados_prop'].get('DISPONIBLE', 0),
         'label': 'Disponibles', 'icon': 'fa-key', 'bg': 'bg-green',
         'url': '/propiedades/'},
        {'num': datos['estados_prop'].get('ALQUILADA', 0),
         'label': 'Alquiladas', 'icon': 'fa-file-signature', 'bg': 'bg-purple',
         'url': '/contratos/'},
        {'num': datos['estados_prop'].get('MANTENIMIENTO', 0),
         'label': 'En mantenimiento', 'icon': 'fa-screwdriver-wrench',
         'bg': 'bg-red', 'url': '/mantenimiento/'},
        {'num': len(activos), 'label': 'Contratos activos',
         'icon': 'fa-folder-open', 'bg': 'bg-dark', 'url': '/contratos/'},
        {'num': f"${sum(r['cobrado'] for r in datos['resumen']):,.0f}",
         'label': 'Cobrado', 'icon': 'fa-credit-card', 'bg': 'bg-green',
         'url': '/pagos/'},
        {'num': f"${sum(r['saldo'] for r in datos['resumen']):,.0f}",
         'label': 'Por cobrar', 'icon': 'fa-triangle-exclamation',
         'bg': 'bg-orange', 'url': '/pagos/'},
        {'num': len([m for m in datos['mans']
                     if m.get('estado') in ('pendiente', 'en_proceso')]),
         'label': 'Mantenimiento abierto', 'icon': 'fa-wrench', 'bg': 'bg-red',
         'url': '/mantenimiento/'},
    ]
    return render(request, 'usuarios/reportes.html', {
        'kpis': kpis,
        'resumen': datos['resumen'],
        'por_mes': datos['por_mes'],
        'tope': datos['tope'],
        'estados_prop': datos['estados_prop'],
        'estados_man': datos['estados_man'],
        'morosos': [r for r in datos['resumen']
                    if r['saldo'] > 0 and r['estado'] == 'activo'],
    })


def _respuesta_csv(tipo, datos):
    import csv
    from django.http import HttpResponse

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if tipo == 'contratos':
        writer.writerow(['contrato', 'vivienda', 'inquilino', 'estado',
                         'inicio', 'fin', 'precio', 'meses_esperados',
                         'meses_pagados', 'cobrado', 'saldo'])
        for r in datos['resumen']:
            writer.writerow([r['id'], r['propiedad'], r['inquilino'], r['estado'],
                             r['inicio'], r['fin'], r['precio'],
                             r['meses_esperados'], r['meses_pagados'],
                             f"{r['cobrado']:.2f}", f"{r['saldo']:.2f}"])
    elif tipo == 'ingresos':
        writer.writerow(['mes', 'pagos', 'total'])
        for f in datos['por_mes']:
            writer.writerow([f['mes'], f['operaciones'], f"{f['total']:.2f}"])
    else:
        writer.writerow(['vivienda', 'direccion', 'estado', 'precio_mensual'])
        for p in datos['props']:
            writer.writerow([p['id'], p['direccion'], p['estado'],
                             p['precio_mensual']])

    response = HttpResponse(buffer.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="reporte_{tipo}.csv"'
    return response


@login_required
@sesion_api_vigente
@rol_requerido('administrador')
def admin_usuarios(request):
    if getattr(request.user, 'rol', None) != 'administrador':
        messages.error(request, 'Solo el administrador gestiona usuarios.')
        return redirect('usuarios:dashboard')

    form_crear = AdminUserCreationForm()

    if request.method == 'POST':
        accion = request.POST.get('accion')
        uid = request.POST.get('usuario_id')
        if accion == 'eliminar':
            en_uso = [
                f'vivienda #{p["id"]} le pertenece'
                for p in (_obtener_de_api(request, "/propiedades/") or [])
                if p.get('propietario_id') == int(uid)
            ] + [
                f'contrato #{c["id"]} lo tiene como inquilino'
                for c in (_obtener_de_api(request, "/contratos/") or [])
                if c.get('inquilino_id') == int(uid)
            ]
            if en_uso:
                messages.error(
                    request,
                    f'No podés eliminar al usuario #{uid}: {", ".join(en_uso[:3])}. '
                    'Eliminá primero esas operaciones.')
                return redirect('usuarios:admin-usuarios')
            resp = _enviar_a_api(request, f"/usuarios/{uid}", method='DELETE')
            if resp is not None and resp.status_code == 204:
                messages.success(request, f'Usuario #{uid} eliminado.')
            else:
                messages.error(request, f"Error: {_detalle_error(resp)}")
        elif accion == 'editar':
            telefono = (request.POST.get('telefono') or '').strip() or None
            payload = {
                'nombre': (request.POST.get('nombre') or '').strip(),
                'email': (request.POST.get('email') or '').strip(),
                'telefono': telefono,
                'rol': request.POST.get('rol'),
                'activo': bool(request.POST.get('activo')),
            }
            clave = (request.POST.get('password') or '').strip()
            if clave:
                payload['password'] = clave
            resp = _enviar_a_api(
                request, f"/usuarios/{uid}", payload, method='PATCH')
            if resp is not None and resp.status_code == 200:
                messages.success(request, f'Usuario #{uid} actualizado.')
            else:
                messages.error(request, f"Error: {_detalle_error(resp)}")
        elif accion == 'crear':
            form_crear = AdminUserCreationForm(request.POST)
            if form_crear.is_valid():
                error = _alta_usuario_api(request, form_crear)
                if error is None:
                    return redirect('usuarios:admin-usuarios')
                messages.error(request, error)
            else:
                primer_error = next(iter(form_crear.errors.values()))[0]
                messages.error(
                    request, f'No se pudo crear el usuario: {primer_error}')
            return render(request, 'usuarios/usuarios_admin.html',
                          _contexto_usuarios(request, form_crear))
        return redirect('usuarios:admin-usuarios')

    return render(request, 'usuarios/usuarios_admin.html',
                  _contexto_usuarios(request, form_crear))


def _contexto_usuarios(request, form_crear):
    buscar = (request.GET.get('buscar') or '').strip()
    rol = (request.GET.get('rol') or '').strip().lower()
    if rol not in ('administrador', 'propietario', 'inquilino', 'visitante'):
        rol = ''
    # La tabla 'usuarios' es de MySQL: en SQLite se consulta la API.
    usuarios = []
    for u in (_obtener_de_api(request, "/usuarios/") or []):
        if not isinstance(u, dict):
            continue
        u['rol'] = (u.get('rol') or '').lower()
        u['activo'] = bool(u.get('activo'))
        u['created_at'] = parse_datetime(u.get('created_at') or '')
        if rol and u['rol'] != rol:
            continue
        if buscar:
            texto = ' '.join(str(u.get(campo) or '') for campo in (
                'nombre', 'email', 'telefono')).lower()
            if buscar.lower() not in texto and not (
                    buscar.isdigit() and u.get('id') == int(buscar)):
                continue
        usuarios.append(u)
    usuarios.sort(key=lambda u: u.get('id') or 0)
    return {
        'usuarios': usuarios,
        'buscar': buscar,
        'rol': rol,
        'form_crear': form_crear,
    }
    
    