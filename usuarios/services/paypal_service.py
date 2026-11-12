
import httpx
import os

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")

PAYPAL_URL = "https://api-m.sandbox.paypal.com"


async def obtener_token():
    async with httpx.AsyncClient() as client:
        respuesta = await client.post(
            f"{PAYPAL_URL}/v1/oauth2/token",
            auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
            data={"grant_type": "client_credentials"}
        )

    respuesta.raise_for_status()
    return respuesta.json()["access_token"]


async def crear_orden(monto, contrato_id):
    token = await obtener_token()

    datos = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": str(contrato_id),
                "amount": {
                    "currency_code": "USD",
                    "value": str(monto)
                }
            }
        ]
    }

    async with httpx.AsyncClient() as client:
        respuesta = await client.post(
            f"{PAYPAL_URL}/v2/checkout/orders",
            json=datos,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )

    respuesta.raise_for_status()
    return respuesta.json()


async def capturar_pago(order_id):
    token = await obtener_token()

    async with httpx.AsyncClient() as client:
        respuesta = await client.post(
            f"{PAYPAL_URL}/v2/checkout/orders/{order_id}/capture",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )

    respuesta.raise_for_status()
    return respuesta.json()
