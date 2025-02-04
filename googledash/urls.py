from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView 
from driveboard.views import RegisterUserView, LoginUserView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
]
