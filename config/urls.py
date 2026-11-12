from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # 1. USUARIOS PRIMERO (Para que '' capture el Dashboard)
    path('', include('usuarios.urls')),

    # 2. ADMIN NATIVO DE DJANGO
    path('admin/', admin.site.urls),

    # 3. APIs INTERNAS (COMENTADAS HASTA QUE LAS CREES)
    # path('api/usuarios/', include('usuarios.api_urls', namespace='api-usuarios')),
    # path('api/propiedades/', include('propiedades.api_urls', namespace='api-propiedades')),
]

# Servir archivos media/uploads en desarrollo
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL,
                          document_root=settings.STATICFILES_DIRS[0])
