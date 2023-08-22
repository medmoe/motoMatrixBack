from django.contrib.postgres.search import SearchVector, SearchQuery
from rest_framework import status, permissions
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Provider
from utils.validators import validate_image
from .models import AutoPart
from .pagination import CustomPageNumberPagination
from .permissions import IsProvider, IsAutoPartOwner, IsProviderApproved
from .serializers import AutoPartSerializer


class AutoPartList(APIView):
    permission_classes = (IsAuthenticated, IsProvider, IsProviderApproved)

    def get(self, request):
        provider = request.user.userprofile.provider
        auto_parts = AutoPart.objects.filter(provider=provider)

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
            raise NotFound(detail="AutoPart not found")

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
            raise ValidationError(detail="No file provided")

        # get the file from the request
        file = request.FILES['file']

        if not validate_image(file):
            raise ValidationError(detail="Uploaded file is not a valid image")

        # Create auto part object with the data we have so far
        AutoPart.objects.create(image=file, provider=Provider.objects.get(user=request.user))

        return Response({'detail': "File uploaded successfully"}, status=status.HTTP_201_CREATED)


class AutoPartSearchView(APIView):
    permission_classes = (IsAuthenticated, IsProvider, IsProviderApproved)

    def get(self, request, *args, **kwargs):
        search_term = request.query_params.get('search', '')

        # Define the search vector and query
        vector = SearchVector('name', 'description', 'category', 'manufacturer', 'condition')
        query = SearchQuery(search_term)

        # Filter auto parts based on ownership and then apply the search criteria
        auto_parts = AutoPart.objects.filter(provider__user=request.user).annotate(search=vector).filter(search=query)

        # Apply pagination
        paginator = CustomPageNumberPagination()
        paginated_auto_parts = paginator.paginate_queryset(auto_parts, request)

        # Serialize and return the response.
        serializer = AutoPartSerializer(paginated_auto_parts, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)
