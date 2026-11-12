from django import forms
from django.contrib import admin
from django.utils import timezone
from lib.pwd import get_password_hash

from .models import UsuarioApi
from .views import ver_solicitudes_alquiler, ver_solicitudes_visita


class UsuarioApiForm(forms.ModelForm):
    password_nueva = forms.CharField(
        label='Contraseña', widget=forms.PasswordInput, required=False,
        help_text='Vacío = dejar la contraseña actual.')

    class Meta:
        model = UsuarioApi
        exclude = ['password']

    def clean_password_nueva(self):
        clave = (self.cleaned_data.get('password_nueva') or '').strip()
        if not self.instance.pk and not clave:
            raise forms.ValidationError('Obligatoria para crear un usuario.')
        if clave and len(clave) < 6:
            raise forms.ValidationError('Mínimo 6 caracteres.')
        return clave


@admin.register(UsuarioApi)
class UsuarioApiAdmin(admin.ModelAdmin):
    form = UsuarioApiForm
    list_display = ['id', 'nombre', 'email', 'telefono', 'rol',
                    'activo', 'created_at']
    list_filter = ['rol', 'activo']
    search_fields = ['nombre', 'email', 'telefono']
    readonly_fields = ['created_at', 'updated_at']

    def save_model(self, request, obj, form, change):
        clave = form.cleaned_data.get('password_nueva')
        if clave:
            obj.password = get_password_hash(clave)
        obj.updated_at = timezone.now()
        super().save_model(request, obj, form, change)

    def get_urls(self):
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path('solicitudes-alquiler/', self.admin_site.admin_view(
                ver_solicitudes_alquiler), name='solicitudes-alquiler'),
            path('solicitudes-visita/', self.admin_site.admin_view(
                ver_solicitudes_visita), name='solicitudes-visita'),
        ]
        return custom_urls + urls
