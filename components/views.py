import logging
from django.contrib.postgres.search import SearchVector
from django.db.models import F, Q
from rest_framework import status, permissions
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.serializers import IMAGE_UPLOAD_ERROR
from utils.validators import validate_image
from .models import AutoPart, Component, Category
from .pagination import CustomPageNumberPagination
from .permissions import IsProvider, IsAutoPartOwner, IsProviderApproved, IsConsumer
from .serializers import AutoPartSerializer, AUTO_PART_NOT_FOUND_ERROR, FILE_NOT_FOUND_ERROR

logger = logging.getLogger(__name__)


class AutoPartList(APIView):
    permission_classes = (IsAuthenticated, IsProvider, IsProviderApproved)

    def get(self, request):
        provider = request.user.userprofile.provider

        auto_parts = AutoPart.objects.filter(component__provider=provider)

        # Apply Pagination
        paginator = CustomPageNumberPagination()
        paginated_auto_parts = paginator.paginate_queryset(auto_parts, request)
        serializer = AutoPartSerializer(paginated_auto_parts, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = AutoPartSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        raise ValidationError(detail=serializer.errors)


class AutoPartDetail(APIView):
    permission_classes = (IsAuthenticated, IsProvider, IsProviderApproved, IsAutoPartOwner)

    def get_object(self, pk):
        try:
            return AutoPart.objects.get(id=pk)
        except AutoPart.DoesNotExist:
            raise NotFound(detail=AUTO_PART_NOT_FOUND_ERROR)

    def check_object_permissions(self, request, obj):
        for permission in self.get_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(request, message=getattr(permission, 'message', None))

    def get(self, request, pk):
        auto_part = self.get_object(pk)
        self.check_object_permissions(request, auto_part)
        serializer = AutoPartSerializer(auto_part)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        auto_part = self.get_object(pk)
        self.check_object_permissions(request, auto_part)
        serializer = AutoPartSerializer(auto_part, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        auto_part = self.get_object(pk)
        self.check_object_permissions(request, auto_part)
        auto_part.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ImageCreation(APIView):
    permission_classes = (permissions.IsAuthenticated, IsProvider, IsProviderApproved)

    def post(self, request):

        # check if the file has been sent with the request
        if 'file' not in request.FILES:
            raise ValidationError(detail=FILE_NOT_FOUND_ERROR)

        # get the file from the request
        file = request.FILES['file']

        if not validate_image(file):
            raise ValidationError(detail=IMAGE_UPLOAD_ERROR)

        # Create auto part object with the data we have so far
        component = Component.objects.create(image=file, provider=request.user.userprofile.provider)
        AutoPart.objects.create(component=component)

        return Response({'detail': "File uploaded successfully"}, status=status.HTTP_201_CREATED)


class ProviderAutoPartSearchView(APIView):
    permission_classes = (IsAuthenticated, IsProvider, IsProviderApproved)

    def get(self, request, *args, **kwargs):
        search_term = request.query_params.get('search', '')
        auto_parts = AutoPart.objects.annotate(
            search=SearchVector("component__name", "category__name")
        )
        # Apply pagination
        paginator = CustomPageNumberPagination()
        paginated_auto_parts = paginator.paginate_queryset(auto_parts, request)

        # Serialize and return the response.
        serializer = AutoPartSerializer(paginated_auto_parts, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)


class ConsumerGetAutoPartsView(APIView):
    permission_classes = (IsAuthenticated, IsConsumer)

    def get(self, request, *args, **kwargs):
        query = Q()
        if request.query_params.get('category'):
            query &= Q(category__name=request.query_params.get('category'))
        if request.query_params.get('make'):
            query &= Q(vehicle_make=request.query_params.get('make'))
        if request.query_params.get('model'):
            query &= Q(vehicle_model=request.query_params.get('model'))
        if request.query_params.get('year'):
            query &= Q(vehicle_year=request.query_params.get('year'))
        if request.query_params.get('name'):
            query &= Q(component__name=request.query_params.get('name'))

        auto_parts = AutoPart.objects.filter(query)
        paginator = CustomPageNumberPagination()
        paginated_auto_parts = paginator.paginate_queryset(auto_parts, request)

        serializer = AutoPartSerializer(paginated_auto_parts, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)
