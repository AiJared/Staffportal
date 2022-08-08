from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from rest_framework.documentation import include_docs_urls

API_TITLE = "Staff Portal"
API_DESCRIPTION = "Employees Portal"


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include_docs_urls(title=API_TITLE,
                                description=API_DESCRIPTION
                                )),
    path("api/v1/", include("api.urls")),
]
urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)