from django.db import models


class SolicitudMantenimiento(models.Model):
    """Espejo (solo lectura) de 'solicitudes_mantenimiento' que maneja la API."""

    class Estado(models.TextChoices):
        # MySQL guarda el NOMBRE del enum de la API, en mayúscula.
        PENDIENTE = 'PENDIENTE', 'Pendiente'
        EN_PROCESO = 'EN_PROCESO', 'En proceso'
        RESUELTO = 'RESUELTO', 'Resuelto'
        CANCELADO = 'CANCELADO', 'Cancelado'

    titulo = models.CharField(max_length=200)
    descripcion = models.CharField(max_length=1000)
    estado = models.CharField(max_length=20, choices=Estado.choices,
                              default=Estado.PENDIENTE)
    propiedad_id = models.IntegerField()
    inquilino_id = models.IntegerField()
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = 'solicitudes_mantenimiento'
        verbose_name = 'Solicitud de mantenimiento'
        verbose_name_plural = 'Solicitudes de mantenimiento'

    def __str__(self):
        return f"#{self.id} {self.titulo} ({self.estado})"


class SolicitudMantenimientoWeb(models.Model):
    """Solicitud creada desde la web, guardada también acá.

    El listado de la API (`GET /mantenimiento/`) responde 500 en el servidor
    actual, así que sin esta copia la solicitud recién enviada no aparecería.
    """

    api_id = models.IntegerField(null=True, blank=True, db_index=True)
    titulo = models.CharField(max_length=200)
    descripcion = models.CharField(max_length=1000)
    estado = models.CharField(max_length=20, default='PENDIENTE')
    propiedad_id = models.IntegerField()
    propiedad_direccion = models.CharField(max_length=255, blank=True)
    inquilino_id = models.IntegerField()
    inquilino_nombre = models.CharField(max_length=150, blank=True)
    creada = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'mantenimiento_solicitudes_web'
        ordering = ['-creada']
        verbose_name = 'Solicitud de mantenimiento (copia web)'
        verbose_name_plural = 'Solicitudes de mantenimiento (copia web)'

    def __str__(self):
        return f"#{self.api_id or self.pk} {self.titulo} ({self.estado})"
