from django.urls import path

from .views import AutoPartList, AutoPartDetail, ImageCreation, AutoPartSearchView

urlpatterns = [
    path('auto-parts/', AutoPartList.as_view(), name="auto-parts"),
    path('auto-parts/<int:pk>/', AutoPartDetail.as_view(), name="auto-part-detail"),
    path('auto-parts/upload-image/', ImageCreation.as_view(), name='upload-file'),
    path('search/', AutoPartSearchView.as_view(), name="autoparts-search")
]
