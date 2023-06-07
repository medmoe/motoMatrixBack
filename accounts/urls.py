from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import SignupView, LogoutView, CustomTokenObtainPairView

urlpatterns = [
    path('signup/', SignupView.as_view(), name="signup"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('login/', CustomTokenObtainPairView.as_view(), name="login"),
    path('refresh/', TokenRefreshView.as_view(), name="refresh"),
]