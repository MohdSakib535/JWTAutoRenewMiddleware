import graphene
from django.contrib.auth import get_user_model
from django.contrib.auth import get_user_model
from graphene_django.types import DjangoObjectType
User = get_user_model()
from .models import Department

class UserType(DjangoObjectType):
    class Meta:
        model = get_user_model()
        fields = ("id", "username", "email", "is_active", "date_joined")  # Add more fields if needed


class DepartmentType(DjangoObjectType):
    class Meta:
        model = Department
        fields = ("id", "name", "description")


"""
query {
  allUsers {
    id
    username
    email
  }
}
"""

class Query(graphene.ObjectType):
    all_users = graphene.List(UserType)
    all_departments = graphene.List(DepartmentType)  # Get all departments
    department = graphene.Field(DepartmentType, id=graphene.Int())  # Get department by ID


    def resolve_all_users(self, info):
        return User.objects.all()
    

    def resolve_all_departments(self, info):
        try:
            # Get authorization header
            auth_header = info.context.META.get('HTTP_AUTHORIZATION', '')
            
            if not auth_header:
                raise GraphQLError('No authorization token provided')

            # Remove Bearer prefix
            token = auth_header.split(' ')[1]

            # Verify token
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload.get('user_id')
                print('user-----',user_id)
                
                if not user_id:
                    raise GraphQLError('Invalid token payload')
                    
                # Add user to context
                info.context.user = User.objects.get(id=user_id)
                print("-----hh----",User.objects.get(id=user_id))
                
            except jwt.ExpiredSignatureError:
                raise GraphQLError('Token has expired')
            except jwt.InvalidTokenError:
                raise GraphQLError('Invalid token')
            except User.DoesNotExist:
                raise GraphQLError('User not found')

            return Department.objects.all()
        except Exception as e:
            raise GraphQLError(str(e))
    
    # def resolve_all_departments(self, info, **kwargs):
    #     user = info.context.user
    #     print('user------depar-----',user)

    #     # Enforce authentication check
    #     if not user.is_authenticated:
    #         raise GraphQLError("Authentication required to view departments")

    #     return Department.objects.all()

    # def resolve_department(self, info, id, **kwargs):
    #     user = info.context.user

    #     # Enforce authentication check
    #     if not user.is_authenticated:
    #         raise GraphQLError("Authentication required to view department details")

    #     try:
    #         return Department.objects.get(id=id)
    #     except Department.DoesNotExist:
    #         return None
    
   




"----------------------Mutation------------------------------------"
from graphene_django.types import DjangoObjectType
from graphql import GraphQLError

from .models import CustomUser

class UserType(DjangoObjectType):
    class Meta:
        model = CustomUser
        fields = ("id", "username", "email")


"""
user Registration


mutation {
  register(
    username: "john_doe"
    email: "john@example.com"
    password1: "securePassword123"
    password2: "securePassword123"
  ) {
    userInstance {
      id
      username
      email
    }
    message
  }
}
"""

class UserRegistration(graphene.Mutation):
    user_instance = graphene.Field(UserType)
    message = graphene.String()
    
    class Arguments:
        username = graphene.String(required=True)
        email = graphene.String(required=True)
        password1 = graphene.String(required=True)
        password2 = graphene.String(required=True)

    def mutate(self, info, username, email, password1, password2):
        if password1 != password2:
            return GraphQLError(message="Passwords do not match.")
        
    
        user = CustomUser(
            username=username,
            email=email,
        )
        user.set_password(password1)
        # user.is_active = False
        user.save()
        message_data="Successfully Resistration"
        return UserRegistration(user_instance=user,message=message_data)
    



"""
Login
"""
import graphql_jwt
import graphene
from graphql_jwt.shortcuts import get_token, get_refresh_token,create_refresh_token
from django.contrib.auth import authenticate
from datetime import datetime, timedelta
from django.conf import settings
import jwt

"""
mutation{
  tokenAuth(
    username:"vikas"
    password :"vikas@123"
  ) {
    success
    message
    accessToken
    refreshToken
    user {
      id
      username
      email
    }
  }
  
}
"""




from django.http import JsonResponse

class CustomObtainJSONWebToken(graphql_jwt.ObtainJSONWebToken):
    success = graphene.Boolean()
    message = graphene.String()
    access_token = graphene.String()
    refresh_token = graphene.String()
    user = graphene.Field(UserType)

    @classmethod
    def resolve(cls, root, info, **kwargs):
        try:
            # Call the built-in authentication logic
            result = super().resolve(root, info, **kwargs)
            user = info.context.user

            if not user.is_authenticated:
                return cls(
                    success=False,
                    message="Invalid credentials",
                    access_token=None,
                    refresh_token=None,
                    user=None
                )

            # Generate tokens with proper claims
            access_token = cls.generate_access_token(user)
            refresh_token = cls.generate_refresh_token(user)

            # Set cookies in response
            request = info.context
            request.graphql_set_cookies = {
                "access_token": {
                    "value": access_token,
                    "max_age": 60
                },
                "refresh_token": {
                    "value": refresh_token,
                    "max_age": 100
                }
            }

            return cls(
                success=True,
                message="Login successful",
                access_token=access_token,
                refresh_token=refresh_token,
                user=user
            )
        except Exception as e:
            return cls(
                success=False,
                message=str(e),
                access_token=None,
                refresh_token=None,
                user=None
            )

    @staticmethod
    def generate_access_token(user):
        now = datetime.utcnow()
        payload = {
            'user_id': user.id,
            'username': user.username,
            'exp': now + timedelta(seconds=60),
            'iat': now,
            'type': 'access'
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    @staticmethod
    def generate_refresh_token(user):
        now = datetime.utcnow()
        payload = {
            'user_id': user.id,
            'username': user.username,
            'exp': now + timedelta(seconds=100),
            'iat': now,
            'type': 'refresh'
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


class CreateDepartment(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        description = graphene.String()

    success = graphene.Boolean()
    message = graphene.String()
    department = graphene.Field(DepartmentType)

    def mutate(self, info, name, description=None):
        user = info.context.user

        # Enforce authentication check
        if not user.is_authenticated:
            raise GraphQLError("Authentication required to create a department")

        # Create department only if user is authenticated
        department = Department(name=name, description=description)
        department.save()

        return CreateDepartment(
            success=True,
            message="Department created successfully",
            department=department
        )


class Mutation(graphene.ObjectType):
    register=UserRegistration.Field()
    token_auth = CustomObtainJSONWebToken.Field()
    verify_token = graphql_jwt.Verify.Field()
    refresh_token = graphql_jwt.Refresh.Field()
    create_department = CreateDepartment.Field()





schema=graphene.Schema(query=Query,mutation=Mutation)