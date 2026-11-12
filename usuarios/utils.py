from django.utils.text import slugify


def username_para_espejo(User, nombre, email, pk):
    """username válido y único para la fila de Django del usuario de la API.

    La API acepta nombres con espacios o acentos, pero el validador de
    username de Django los rechaza en full_clean().
    """
    base = slugify(nombre or '').replace('-', '_') or email
    candidato = base
    sufijo = 2
    while User.objects.filter(username=candidato).exclude(pk=pk).exists():
        candidato = f'{base}_{sufijo}'
        sufijo += 1
    return candidato
