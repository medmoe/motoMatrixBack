from django.urls import path
from .views import AutoPartList, AutoPartDetail

urlpatterns = [
    path('auto-parts/', AutoPartList.as_view(), name="auto-parts"),
    path('auto-parts/<int:id>/', AutoPartDetail.as_view(), name="auto-part-detail"),
]
