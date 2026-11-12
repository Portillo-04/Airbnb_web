from django.db import models


class Pago(models.Model):
    """Espejo (solo lectura) de la tabla 'pagos' que maneja la API."""

    class Metodo(models.TextChoices):
        # MySQL guarda el NOMBRE del enum de la API, en mayúscula.
        EFECTIVO = 'EFECTIVO', 'Efectivo'
        TRANSFERENCIA = 'TRANSFERENCIA', 'Transferencia'
        TARJETA = 'TARJETA', 'Tarjeta'

    fecha_pago = models.DateField()
    monto = models.DecimalField(max_digits=10, decimal_places=2)
    metodo_pago = models.CharField(max_length=20, choices=Metodo.choices,
                                   default=Metodo.EFECTIVO)
    descripcion = models.CharField(max_length=255, null=True, blank=True)
    meses_cubiertos = models.IntegerField(default=1)
    contrato_id = models.IntegerField()
    created_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = 'pagos'
        verbose_name = 'Pago'
        verbose_name_plural = 'Pagos'

    def __str__(self):
        return f"Pago #{self.id} · {self.fecha_pago} · {self.monto} ({self.metodo_pago})"


class PagoPendiente(models.Model):
    """Pago avisado por el inquilino que el administrador debe aprobar."""

    class Estado(models.TextChoices):
        PENDIENTE = 'pendiente', 'Pendiente'
        APROBADO = 'aprobado', 'Aprobado'
        RECHAZADO = 'rechazado', 'Rechazado'

    class Metodo(models.TextChoices):
        EFECTIVO = 'efectivo', 'Efectivo'
        TARJETA = 'tarjeta', 'Tarjeta'

    contrato_id = models.IntegerField()
    inquilino_id = models.IntegerField()
    monto = models.DecimalField(max_digits=10, decimal_places=2)
    meses_cubiertos = models.IntegerField(default=1)
    fecha_pago = models.DateField()
    metodo = models.CharField(max_length=10, choices=Metodo.choices,
                              default=Metodo.TARJETA)
    paypal_order_id = models.CharField(
        max_length=64, unique=True, null=True, blank=True)
    descripcion = models.CharField(max_length=255, null=True, blank=True)
    estado = models.CharField(max_length=12, choices=Estado.choices,
                              default=Estado.PENDIENTE)
    pago_id = models.IntegerField(null=True, blank=True)
    creado = models.DateTimeField(auto_now_add=True)
    revisado_por = models.CharField(max_length=150, null=True, blank=True)
    revisado = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'pagos_pendientes'
        verbose_name = 'Pago pendiente'
        verbose_name_plural = 'Pagos pendientes'
        ordering = ['-creado']

    def __str__(self):
        return (f"{self.get_metodo_display()} · contrato #{self.contrato_id} "
                f"· {self.monto} ({self.estado})")
