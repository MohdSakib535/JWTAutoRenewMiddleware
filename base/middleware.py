# class CookieJWTMiddleware:
#     """
#     Middleware that extracts the JWT token from cookies and adds it to the
#     Authorization header so that django-graphql-jwt can pick it up.
#     """
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         # If there is no Authorization header, check the cookies
#         if "HTTP_AUTHORIZATION" not in request.META:
#             token = request.COOKIES.get("access_token")
#             if token:
#                 # Prepend "JWT " so it matches what django-graphql-jwt expects.
#                 request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
#         response = self.get_response(request)
#         return response
    



import jwt
from django.conf import settings
from django.contrib.auth import get_user_model, logout
from django.shortcuts import redirect
from base.schema import CustomObtainJSONWebToken  # Adjust this path as needed
from django.http import JsonResponse
import json

class RefreshTokenMiddleware:
    """
    Middleware that checks for a valid access token.
      - If the access token exists and is valid, it is used.
      - If the access token is expired, it attempts to use the refresh token
        to generate a new access token.
      - If the refresh token is invalid or missing, the user is logged out.
    
    This middleware inspects the GraphQL request payload so that when the login
    mutation is executed, the refresh logic is bypassed. For all other operations,
    the middleware runs as normal.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print("Request path:", request.path)

        # Since your only endpoint is /graphql/, we must inspect the request body.
        if request.path.startswith("/graphql/"):
            login_mutation_detected = self._is_login_mutation(request)
            if login_mutation_detected:
                # Bypass refresh token logic so that the login mutation runs unimpeded.
                print("Login mutation detected. Bypassing refresh token middleware.")
                return self.get_response(request)

        # For non-login operations, run the token verification/refresh logic.
        should_logout = False
        access_token = request.COOKIES.get("access_token")

        if not access_token:
            print("No access token found; checking refresh token...")
            refresh_token = request.COOKIES.get("refresh_token")
            if refresh_token:
                should_logout = not self._handle_refresh_token(request, refresh_token)
                print("After refresh token check, should_logout =", should_logout)
            else:
                should_logout = True
        else:
            print("Access token found; verifying...")
            try:
                # Try to decode the access token.
                jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
            except jwt.ExpiredSignatureError:
                print("Access token expired; attempting refresh...")
                refresh_token = request.COOKIES.get("refresh_token")
                if refresh_token:
                    should_logout = not self._handle_refresh_token(request, refresh_token)
                else:
                    should_logout = True
            except jwt.InvalidTokenError:
                print("Invalid access token.")
                should_logout = True

        if should_logout:
            logout(request)
            return self._handle_logout(request)

        # Process the request normally.
        response = self.get_response(request)

        # If a new access token was generated, set it in a cookie.
        if hasattr(request, "new_access_token"):
            response.set_cookie(
                key="access_token",
                value=request.new_access_token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite="Lax",
                max_age=60  # Ensure this matches your access token lifetime.
            )

        return response

    def _is_login_mutation(self, request):
        """
        Inspects the request body to determine if it is the login mutation.
        This example assumes the login mutation's name is "CustomObtainJSONWebToken".
        You can modify the check to look for another string or parse the JSON payload.
        """
        try:
            # The request body for a GraphQL POST request is usually JSON.
            body = request.body.decode("utf-8")
            # Attempt to load it as JSON
            data = json.loads(body)
            # Check for a key like "operationName" or "query"
            # If you have an operation name, you might check:
            if data.get("operationName") == "CustomObtainJSONWebToken":
                return True
            # Alternatively, inspect the query string.
            query = data.get("query", "")
            if "mutation CustomObtainJSONWebToken" in query or "tokenAuth" in query:
                return True
        except Exception as e:
            print("Error parsing GraphQL body:", e)
        return False

    def _handle_refresh_token(self, request, refresh_token):
        """
        Validates the refresh token and, if valid, generates a new access token.
        Returns True if successful; otherwise, returns False.
        """
        try:
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
            print("Refresh token payload:", payload)
            if payload and payload.get("type") == "refresh":
                user_id = payload.get("user_id")
                User = get_user_model()
                try:
                    user = User.objects.get(id=user_id)
                    new_access_token = CustomObtainJSONWebToken.generate_access_token(user)
                    request.META["HTTP_AUTHORIZATION"] = f"Bearer {new_access_token}"
                    request.new_access_token = new_access_token
                    print("New access token generated successfully.")
                    return True
                except User.DoesNotExist:
                    print("User not found for refresh token.")
                    return False
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            print("Error decoding refresh token:", e)
            return False
        return False

    def _handle_logout(self, request):
        """
        Handles logout by returning a JSON response indicating that authentication is required.
        This avoids using redirects in a GraphQL-only API.
        """
        response = JsonResponse(
            {"error": "Authentication required. Please log in again."},
            status=401
        )
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response