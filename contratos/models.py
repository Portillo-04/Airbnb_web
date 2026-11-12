from django.db import models


class Contrato(models.Model):
    """Espejo (solo lectura) de la tabla 'contratos' que maneja la API."""

    class Estado(models.TextChoices):
        # MySQL guarda el NOMBRE del enum de la API, en mayúscula.
        ACTIVO = 'ACTIVO', 'Activo'
        FINALIZADO = 'FINALIZADO', 'Finalizado'
        CANCELADO = 'CANCELADO', 'Cancelado'

    fecha_inicio = models.DateField()
    fecha_fin = models.DateField()
    precio_mensual = models.DecimalField(max_digits=10, decimal_places=2)
    estado = models.CharField(max_length=20, choices=Estado.choices,
                              default=Estado.ACTIVO)
    propiedad_id = models.IntegerField()
    inquilino_id = models.IntegerField()
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = 'contratos'
        verbose_name = 'Contrato'
        verbose_name_plural = 'Contratos'

    def __str__(self):
        return (f"Contrato #{self.id} · propiedad {self.propiedad_id} · "
                f"inquilino {self.inquilino_id} ({self.estado})")


class ContratoWeb(models.Model):
    """Copia local de los contratos vistos o creados desde la web.

    La API solo deja listar `/contratos/` al administrador; sin esta copia,
    inquilinos y propietarios no pueden ver sus contratos ni pagar. Se llena
    cuando el admin abre Contratos y cuando se crea uno desde el panel.
    """

    api_id = models.IntegerField(unique=True)
    propiedad_id = models.IntegerField()
    inquilino_id = models.IntegerField()
    fecha_inicio = models.DateField()
    fecha_fin = models.DateField()
    precio_mensual = models.DecimalField(max_digits=10, decimal_places=2)
    estado = models.CharField(max_length=20, default='activo')
    pdf_url = models.CharField(max_length=500, null=True, blank=True)
    propiedad_direccion = models.CharField(max_length=255, blank=True)
    inquilino_nombre = models.CharField(max_length=150, blank=True)
    actualizado = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'contratos_web'
        ordering = ['-api_id']
        verbose_name = 'Contrato (copia web)'
        verbose_name_plural = 'Contratos (copia web)'

    def __str__(self):
        return f"Contrato #{self.api_id} · propiedad {self.propiedad_id}"


class SolicitudAlquilerWeb(models.Model):
    """Solicitud de alquiler creada o respondida desde la web.

    El servidor actual responde 500 al crear solicitudes y no se las devuelve
    a propietarios ni inquilinos; esta copia permite pedir, ver y responder
    aunque la API falle. Cuando la API vuelve a listar la solicitud, se
    reconcilia por api_id.
    """

    api_id = models.IntegerField(null=True, blank=True, db_index=True)
    propiedad_id = models.IntegerField()
    propiedad_direccion = models.CharField(max_length=255, blank=True)
    inquilino_id = models.IntegerField()
    inquilino_nombre = models.CharField(max_length=150, blank=True)
    fecha_inicio = models.DateField()
    fecha_fin = models.DateField()
    estado = models.CharField(max_length=20, default='PENDIENTE')
    respuesta_propietario = models.CharField(max_length=500, blank=True)
    # True solo cuando la API no confirmó el alta o la respuesta: esos
    # cambios locales mandan sobre lo que devuelva el listado.
    pendiente_sync = models.BooleanField(default=False)
    creada = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'solicitudes_alquiler_web'
        ordering = ['-creada']
        verbose_name = 'Solicitud de alquiler (copia web)'
        verbose_name_plural = 'Solicitudes de alquiler (copia web)'

    def __str__(self):
        return (f"#{self.api_id or self.pk} propiedad {self.propiedad_id} "
                f"({self.estado})")
