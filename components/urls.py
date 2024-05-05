from django.urls import path

from .views import AutoPartList, AutoPartDetail, ImageCreation, ProviderAutoPartSearchView, ConsumerGetAutoPartsView

urlpatterns = [
    # Provider end points
    path('auto-parts/', AutoPartList.as_view(), name="auto-parts"),
    path('auto-parts/<int:pk>/', AutoPartDetail.as_view(), name="auto-part-detail"),
    path('auto-parts/upload-image/', ImageCreation.as_view(), name='upload-file'),
    path('search/', ProviderAutoPartSearchView.as_view(), name="autoparts-search"),

    # Consumer end points
    path('get-auto-parts/', ConsumerGetAutoPartsView.as_view(), name="get-auto-parts")
]
