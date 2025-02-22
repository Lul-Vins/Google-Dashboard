from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView 
from driveboard.views import RegisterUserView, LoginUserView, IdeahistoriaView, HistorialdeArchivosView
from rest_framework.routers import DefaultRouter
from driveboard import views
from driveboard.views import login_view, dashboard_view, crear_idea




router = DefaultRouter()
router.register(r'ideas', IdeahistoriaView, basename = 'ideas')
router.register(r'historial', HistorialdeArchivosView, basename= 'historial')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('', include(router.urls)),
    path('google-auth/', views.google_oauth, name='google_auth'),
    path('google-callback/', views.google_auth_callback, name='google_auth_callback'),
    path("login/", login_view, name="login"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("crear-idea/", crear_idea, name="crear_idea"),
]
