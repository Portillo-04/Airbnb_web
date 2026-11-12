from django.urls import path
from .views import PropiedadListCreateView, PropiedadDetailView, PropiedadDisponiblesView

urlpatterns = [
    path('', PropiedadListCreateView.as_view(), name='propiedad-list'),
    path('disponibles/', PropiedadDisponiblesView.as_view(),
         name='propiedad-disponibles'),
    path('<int:pk>/', PropiedadDetailView.as_view(), name='propiedad-detail'),
]
