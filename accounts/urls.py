from django.urls import path
from .views import SignupView, LogoutView, CustomTokenObtainPairView, CustomTokenRefreshView

urlpatterns = [
    path('signup/', SignupView.as_view(), name="signup"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('login/', CustomTokenObtainPairView.as_view(), name="login"),
    path('refresh/', CustomTokenRefreshView.as_view(), name="refresh"),
]
