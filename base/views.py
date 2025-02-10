from django.shortcuts import render
from graphene_django.views import GraphQLView
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Create your views here.

# class CustomGraphQLView(GraphQLView):
#     @method_decorator(csrf_exempt)
#     def dispatch(self, request, *args, **kwargs):
#         response = super().dispatch(request, *args, **kwargs)

#         # Ensure response is attached to context for mutations
#         request.graphql_response = response
#         return response


from django.conf import settings
# class CustomGraphQLView(GraphQLView):
#     @method_decorator(csrf_exempt)
#     def dispatch(self, request, *args, **kwargs):
#         # Process the GraphQL request and obtain the response
#         response = super().dispatch(request, *args, **kwargs)
        
#         # If tokens were attached to the request, set them as cookies on the response
#         if hasattr(request, "graphql_set_cookies"):
#             cookies = request.graphql_set_cookies
#             for key, cookie_opts in cookies.items():
#                 response.set_cookie(
#                     key=key,
#                     value=cookie_opts.get("value"),
#                     httponly=True,
#                     secure=not settings.DEBUG,  # Ensure this matches your environment (use False in development if needed)
#                     samesite="Lax",
#                     max_age=cookie_opts.get("max_age")
#                 )
#         return response




from graphql_jwt.middleware import JSONWebTokenMiddleware

class CustomGraphQLView(GraphQLView):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        # Before processing the request, check if the token is in cookies
        if "HTTP_AUTHORIZATION" not in request.META:
            token = request.COOKIES.get("access_token")
            if token:
                request.META["HTTP_AUTHORIZATION"] = f"JWT {token}"

        # Process the GraphQL request
        response = super().dispatch(request, *args, **kwargs)

        # Set the cookies if present (your existing logic)
        if hasattr(request, "graphql_set_cookies"):
            cookies = request.graphql_set_cookies
            for key, cookie_opts in cookies.items():
                response.set_cookie(
                    key=key,
                    value=cookie_opts.get("value"),
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite="Lax",
                    max_age=cookie_opts.get("max_age")
                )
        return response
