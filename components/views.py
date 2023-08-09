from rest_framework import status, permissions
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import UserProfile, Provider
from utils.validators import validate_image
from .models import AutoPart
from .serializers import AutoPartSerializer


class AutoPartList(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        auto_parts = AutoPart.objects.filter(provider=request.user.userprofile.provider)
        serializer = AutoPartSerializer(auto_parts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = AutoPartSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class AutoPartDetail(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self, pk, request):
        try:
            auto_part = AutoPart.objects.get(id=pk)
            if auto_part.provider != request.user.userprofile.provider:
                raise PermissionDenied("You do not have permission to perform this action")
            return auto_part
        except AutoPart.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        auto_part = self.get_object(pk, request)
        serializer = AutoPartSerializer(auto_part)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        auto_part = self.get_object(pk, request)
        serializer = AutoPartSerializer(auto_part, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

    def delete(self, request, pk):
        auto_part = self.get_object(pk, request)
        auto_part.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ImageCreation(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        # Make sure the user is a provider
        try:
            userprofile = UserProfile.objects.get(user=request.user)
            if not userprofile.is_provider:
                raise ValidationError(detail="You don't have permission to perform this action")

            provider = Provider.objects.get(userprofile_ptr_id=userprofile.id)
        except UserProfile.DoesNotExist:
            raise NotFound(detail="User profile not found")

        # check if the file has been sent with the request
        if 'image' not in request.FILES:
            raise ValidationError(detail="No file provided")

        # get the file from the request
        file = request.FILES['image']

        if not validate_image(file):
            raise ValidationError(detail="Uploaded file is not a valid image")

        # Create auto part object with the data we have so far
        auto_part = AutoPart.objects.create(image=file, provider=provider)

        return Response({'detail': "File uploaded successfully"}, status=status.HTTP_201_CREATED)
