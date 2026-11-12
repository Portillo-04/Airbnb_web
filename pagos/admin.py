from django.contrib import admin
from .models import Pago


@admin.register(Pago)
class PagoAdmin(admin.ModelAdmin):
    list_display = ['id', 'fecha_pago', 'monto', 'metodo_pago',
                    'contrato_id', 'descripcion']
    list_filter = ['metodo_pago', 'fecha_pago']
    search_fields = ['descripcion', 'contrato_id']
    readonly_fields = ['contrato_id', 'created_at']
