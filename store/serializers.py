from django.db.models import Avg, Q
from rest_framework import serializers


from .models import (Orders, Product)
from accounts.models import User


import logging

logger = logging.getLogger(__name__)


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Orders
        fields = '__all__'

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'