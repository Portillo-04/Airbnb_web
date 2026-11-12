from django.contrib import admin
from .models import SolicitudMantenimiento


@admin.register(SolicitudMantenimiento)
class SolicitudMantenimientoAdmin(admin.ModelAdmin):
    list_display = ['id', 'titulo', 'estado', 'propiedad_id',
                    'inquilino_id', 'created_at']
    list_filter = ['estado']
    search_fields = ['titulo', 'descripcion']
    readonly_fields = ['propiedad_id', 'inquilino_id',
                       'created_at', 'updated_at']
