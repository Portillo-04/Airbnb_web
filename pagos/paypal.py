
"""Cliente mínimo de PayPal Orders v2 para el pago online del alquiler."""

import requests
from decouple import config

SANDBOX = "https://api-m.sandbox.paypal.com"
LIVE = "https://api-m.paypal.com"
TIMEOUT = 20


def client_id():
    return config("PAYPAL_CLIENT_ID", default="")


def configurado():
    return bool(
        client_id()
        and config("PAYPAL_CLIENT_SECRET", default="")
    )


def moneda():
    return config("PAYPAL_CURRENCY", default="USD").upper()


def _base():
    modo = config("PAYPAL_MODE", default="sandbox").strip().lower()
    return LIVE if modo == "live" else SANDBOX


def _token():
    respuesta = requests.post(
        f"{_base()}/v1/oauth2/token",
        auth=(
            client_id(),
            config("PAYPAL_CLIENT_SECRET", default="")
        ),
        data={"grant_type": "client_credentials"},
        timeout=TIMEOUT,
    )

    respuesta.raise_for_status()
    return respuesta.json()["access_token"]


def _cabeceras(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def crear_orden(monto, descripcion, referencia):
    token = _token()

    respuesta = requests.post(
        f"{_base()}/v2/checkout/orders",
        headers=_cabeceras(token),
        json={
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": str(referencia),
                "custom_id": str(referencia),
                "description": (descripcion or "")[:127],
                "amount": {
                    "currency_code": moneda(),
                    "value": f"{float(monto):.2f}",
                },
            }],
        },
        timeout=TIMEOUT,
    )

    respuesta.raise_for_status()
    return respuesta.json()


def obtener_orden(orden_id):
    token = _token()

    respuesta = requests.get(
        f"{_base()}/v2/checkout/orders/{orden_id}",
        headers=_cabeceras(token),
        timeout=TIMEOUT,
    )

    respuesta.raise_for_status()
    return respuesta.json()


def capturar_orden(orden_id):
    token = _token()

    respuesta = requests.post(
        f"{_base()}/v2/checkout/orders/{orden_id}/capture",
        headers=_cabeceras(token),
        json={},
        timeout=TIMEOUT,
    )

    if respuesta.status_code == 422:
        return obtener_orden(orden_id)

    respuesta.raise_for_status()
    return respuesta.json()


def error_legible(exc):
    """Mensaje corto a partir del JSON de error de PayPal."""

    respuesta = getattr(exc, "response", None)

    if respuesta is not None:
        try:
            detalle = respuesta.json()
            problema = detalle.get("details") or []

            if problema:
                return (
                    problema[0].get("description")
                    or detalle.get("message")
                )

            return (
                detalle.get("message")
                or detalle.get("error_description")
            )

        except ValueError:
            pass

    return "No se pudo comunicar con PayPal."
