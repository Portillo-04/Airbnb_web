from django.db import models


class EstadoPropiedad(models.TextChoices):
    DISPONIBLE = 'DISPONIBLE', 'Disponible'
    ALQUILADA = 'ALQUILADA', 'Alquilada'
    MANTENIMIENTO = 'MANTENIMIENTO', 'En Mantenimiento'


class Propiedad(models.Model):
    """Espejo de la tabla 'propiedades' que crea y mantiene la API."""

    direccion = models.CharField(max_length=255)
    descripcion = models.CharField(max_length=1000)
    precio_mensual = models.DecimalField(max_digits=10, decimal_places=2)
    estado = models.CharField(
        max_length=20,
        choices=EstadoPropiedad.choices,
        default=EstadoPropiedad.DISPONIBLE
    )
    # La API guarda rutas relativas (/uploads/propiedades/xxx.jpg), no URLs.
    imagen_url = models.CharField(max_length=500, blank=True, null=True)
    propietario_id = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'propiedades'
        verbose_name = 'Propiedad'
        verbose_name_plural = 'Propiedades'

    def __str__(self):
        return f"#{self.id} {self.direccion} ({self.estado})"


class EstadoPropiedadWeb(models.Model):
    """Cambios de una vivienda guardados en la web cuando la API falla.

    La API responde 500 al actualizar propiedades en el servidor actual; este
    registro conserva el estado y los datos editados desde el panel para que
    los listados y las acciones sigan funcionando.
    """

    propiedad_id = models.IntegerField(unique=True)
    estado = models.CharField(max_length=20, choices=EstadoPropiedad.choices)
    direccion = models.CharField(max_length=255, blank=True)
    descripcion = models.CharField(max_length=1000, blank=True)
    precio_mensual = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True)
    actualizado = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'propiedades_estado_web'
        verbose_name = 'Cambios de vivienda (copia web)'
        verbose_name_plural = 'Cambios de vivienda (copia web)'

    def __str__(self):
        return f"#{self.propiedad_id} {self.estado}"
