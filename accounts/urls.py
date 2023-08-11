from django.urls import path

from .views import \
    SignupView, \
    LogoutView, \
    CustomTokenObtainPairView, \
    CustomTokenRefreshView, \
    ProfileDetail, \
    FileUpload, \
    CheckAuthView

urlpatterns = [
    path('signup/', SignupView.as_view(), name="signup"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('login/', CustomTokenObtainPairView.as_view(), name="login"),
    path('refresh/', CustomTokenRefreshView.as_view(), name="refresh"),
    path('check-auth/', CheckAuthView.as_view(), name="check-auth"),
    # update profile information
    path('<str:is_provider>/<int:account_id>/', ProfileDetail.as_view(), name="update_profile"),
    path('files/<str:is_provider>/<int:account_id>/', FileUpload.as_view(), name="file_upload"),

    # added path for a view here that handles paths that are out of scope of the app
]
