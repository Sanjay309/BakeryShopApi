from django.shortcuts import render
from .models import Orders, Product
from rest_framework import status
from rest_framework.permissions import (IsAuthenticated,
                                        IsAuthenticatedOrReadOnly,AllowAny)
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework.exceptions import (MethodNotAllowed, NotFound,
                                       PermissionDenied)
from rest_framework.generics import ListAPIView

from .serializers import (OrderSerializer,ProductSerializer) 
from .permissions import IsAdmin


# Create your views here.
class OrderViewSet(ModelViewSet):
    queryset = Orders.objects.select_related('coustomer')
    permission_classes = [IsAuthenticatedOrReadOnly | IsAdmin]
    serializer_class = OrderSerializer
    list_serializer_class = OrderSerializer
    

    def get_queryset(self):
        return self.queryset
        # INFO: not needed now
        queryset = self.queryset
        return queryset

    def create(self, request):
        serializer_context = {
            'request': request
        }
        serializer_data = request.data.get('order', {})

        serializer = self.serializer_class(
            data=serializer_data, context=serializer_context
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request):
        serializer_context = {'request': request}
        page = self.paginate_queryset(self.get_queryset())

        serializer = self.list_serializer_class(
            page,
            context=serializer_context,
            many=True
        )

        return self.get_paginated_response(serializer.data)
    
   

    def partial_update(self, request, pk):        
        try:
            order_instance = self.queryset.get(pk=pk)
        except Orders.DoesNotExist:
            raise NotFound('Order does not exist')
        serializer_context = {'request': request}

        serializer_data = request.data.get('order', {})

        serializer = self.serializer_class(
            order_instance,
            context=serializer_context,
            data=serializer_data,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)

class ProductViewSet(ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated | IsAdmin]
    list_serializer_class = ProductSerializer
    

    def get_queryset(self):
        return self.queryset
        # INFO: not needed now
        queryset = self.queryset
        return queryset

    def create(self, request):
        serializer_context = {
            'request': request
        }
        serializer_data = request.data.get('product', {})

        serializer = self.serializer_class(
            data=serializer_data, context=serializer_context
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request):
        serializer_context = {'request': request}
        page = self.paginate_queryset(self.get_queryset())

        serializer = self.list_serializer_class(
            page,
            context=serializer_context,
            many=True
        )

        return self.get_paginated_response(serializer.data)
    

    def partial_update(self, request, pk):        
        try:
            product_instance = self.queryset.get(pk=pk)
        except Product.DoesNotExist:
            raise NotFound('Product does not exist')
        serializer_context = {'request': request}

        serializer_data = request.data.get('product', {})

        serializer = self.serializer_class(
            product_instance,
            context=serializer_context,
            data=serializer_data,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)
    def partial_update(self, request, pk):        
        try:
            product_instance = self.queryset.get(pk=pk)
        except Product.DoesNotExist:
            raise NotFound('Product does not exist')
        serializer_context = {'request': request}

        serializer_data = request.data.get('product', {})

        serializer = self.serializer_class(
            product_instance,
            context=serializer_context,
            data=serializer_data,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)

class OrderHistoryView(ListAPIView):
    serializer_class = OrderSerializer
    queryset = Orders.objects.all()
    permission_classes = [IsAuthenticated | IsAdmin]

    def get_queryset(self):
        print(self.request.user.id)
        queryset = self.queryset.filter(coustomer=self.request.user)
        return queryset

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)