from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed


class CookieJWTAuthentication(JWTAuthentication):
    def get_header(self, request):
        return request.COOKIES.get('access')

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        try:
            validated_token = self.get_validated_token(header)
            return self.get_user(validated_token), validated_token
        except InvalidToken:
            raise AuthenticationFailed('Access token is invalid or expired')
