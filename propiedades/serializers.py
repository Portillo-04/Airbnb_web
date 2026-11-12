from rest_framework import serializers
from .models import Propiedad


class PropiedadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Propiedad
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']
