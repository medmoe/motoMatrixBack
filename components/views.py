from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import AutoPartSerializer
from .models import AutoPart


class AutoPartList(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        auto_parts = AutoPart.objects.all()
        serializer = AutoPartSerializer(auto_parts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = AutoPartSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class AutoPartDetail(APIView):
    def get_object(self, id):
        try:
            return AutoPart.objects.get(id=id)
        except AutoPart.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, id):
        auto_part = self.get_object(id)
        serializer = AutoPartSerializer(auto_part)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, id):
        auto_part = self.get_object(id)
        serializer = AutoPartSerializer(auto_part, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

    def delete(self, request, id):
        auto_part = self.get_object(id)
        auto_part.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
