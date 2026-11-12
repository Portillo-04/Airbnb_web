from django.contrib import admin
from .models import Propiedad


@admin.register(Propiedad)
class PropiedadAdmin(admin.ModelAdmin):
    list_display = ['id', 'direccion', 'propietario_id', 'estado',
                    'precio_mensual', 'created_at']
    list_filter = ['estado', 'propietario_id', 'created_at']
    search_fields = ['direccion', 'descripcion']
    readonly_fields = ['created_at', 'updated_at']
