from django.contrib import admin, messages
from django.urls import reverse

from .models import Contrato


@admin.register(Contrato)
class ContratoAdmin(admin.ModelAdmin):
    list_display = ['id', 'fecha_inicio', 'fecha_fin', 'precio_mensual',
                    'estado', 'propiedad_id', 'inquilino_id']
    list_filter = ['estado', 'fecha_inicio']
    search_fields = ['propiedad_id', 'inquilino_id']
    readonly_fields = ['propiedad_id', 'inquilino_id',
                       'created_at', 'updated_at']

    # La tabla 'contratos' es un espejo: escribirla desde acá saltea la API y
    # deja la vivienda sin pasar a ALQUILADA / DISPONIBLE.
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        messages.info(
            request,
            'Los contratos se crean y cierran desde "Contratos" en el panel '
            f'de la web ({reverse("usuarios:contratos")}). Así la API actualiza '
            'el estado de la vivienda.')
        return super().changelist_view(request, extra_context)
