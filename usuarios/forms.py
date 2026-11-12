from django import forms


class AdminUserCreationForm(forms.Form):
    nombre = forms.CharField(
        label='Nombre completo',
        max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'Ej. Juan Pérez'})
    )
    email = forms.EmailField(
        label='Correo electrónico',
        widget=forms.EmailInput(attrs={'placeholder': 'usuario@gmail.com'})
    )
    telefono = forms.CharField(
        label='Teléfono',
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': '0991-2345'})
    )
    password = forms.CharField(
        label='Contraseña',
        widget=forms.PasswordInput(
            attrs={'placeholder': 'Mínimo 6 caracteres'}),
        min_length=6
    )
    password2 = forms.CharField(
        label='Confirmar contraseña',
        widget=forms.PasswordInput(
            attrs={'placeholder': 'Repetir contraseña'}),
        min_length=6
    )
    activo = forms.BooleanField(
        label='Usuario activo', required=False, initial=True)

    ROL_CHOICES = [
        ('administrador', 'Administrador'),
        ('propietario', 'Propietario'),
        ('inquilino', 'Inquilino'),
        ('visitante', 'Visitante'),
    ]
    rol = forms.ChoiceField(label='Rol del usuario', choices=ROL_CHOICES)

    def clean(self):
        datos = super().clean()
        clave = datos.get('password')
        clave2 = datos.get('password2')
        if clave and clave2 and clave != clave2:
            self.add_error('password2', 'Las contraseñas no coinciden.')
        return datos
