from django.urls import path, include

from rest_framework.routers import DefaultRouter

from .views import (OrderViewSet,ProductViewSet,OrderHistoryView)


router = DefaultRouter(trailing_slash=False)
router.register(r'orders', OrderViewSet)
router.register(r'products', ProductViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('order-history/', OrderHistoryView.as_view(),name="list-order-history"),
]

