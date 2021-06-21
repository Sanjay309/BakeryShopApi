import datetime
import logging
import requests
import json
from django.http import JsonResponse
from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import (GenericAPIView, ListAPIView,
                                     RetrieveAPIView, RetrieveUpdateAPIView)
from rest_framework.mixins import CreateModelMixin, ListModelMixin
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenViewBase



from .models import PasswordReset, User

from .serializers import (AccountsTokenObtainPairSerializer, 
                          ForgotPasswordSerializer, 
                          LoginSerializer, RegistrationSerializer,
                          UserSerializer)
from .serializers import RefreshTokenMixin
from .utils import decode_uid,encode_uid


from uuid import UUID 
from django.contrib.auth.tokens import default_token_generator

logger = logging.getLogger(__name__)


class RegistrationAPIView(RefreshTokenMixin,APIView):
    # Allow any user (authenticated or not) to hit this endpoint.
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer

    def post(self, request):
        user_data = request.data.get('user', {})
        user_data['password_last_updated_at'] = timezone.now()

        # The create serializer, validate serializer, save serializer pattern
        # below is common and you will see it a lot throughout this course and
        # your own work later on. Get familiar with it.
        serializer = self.serializer_class(data=user_data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return_data = serializer.data
        refresh = self.get_token(user)
        return_data['refresh'] = str(refresh)
        return_data['token'] = str(refresh.access_token)

        return Response(return_data, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request):
        user = request.data.get('user', {})

        # Notice here that we do not call `serializer.save()` like we did for
        # the registration endpoint. This is because we don't actually have
        # anything to save. Instead, the `validate` method on our serializer
        # handles everything we need.
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class AccountsTokenObtainPairView(TokenViewBase):
    serializer_class = AccountsTokenObtainPairSerializer


    def post(self, request, *args, **kwargs):
        user = request.data.get('user', {})
        serializer = self.get_serializer(data=user)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data, status=status.HTTP_200_OK)



class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def retrieve(self, request, *args, **kwargs):
        # There is nothing to validate or save here. Instead, we just want the
        # serializer to handle turning our `User` object into something that
        # can be JSONified and sent to the client.
        serializer = self.serializer_class(request.user)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        user_data = request.data.get('user', {})

        serializer_data = {
            'username': user_data.get('username', request.user.username),
            'email': user_data.get('email', request.user.email),
        }

        # Here is that serialize, validate, save pattern we talked about
        # before.
        serializer = self.serializer_class(
            request.user, data=serializer_data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


from rest_framework.generics import GenericAPIView

from .serializers import RefreshTokenSerializer


class LogoutAPIView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = RefreshTokenSerializer

    def post(self, request, *args):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ForgotPasswordAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        # always return success, even if email not found, this will prevent user existance checking with brute force
        response = {'status': 'success'}
        data = request.data.get('user', {})
        email = data.get('email', None)
        if not email:
            raise ValidationError('Invalid Email address')

        user = User.objects.filter(email=email).first()

        # If no user was found matching this email, Raise an exception.
        if user.password_last_updated_at is None:
            # return Response(response, status=status.HTTP_200_OK)
            raise ValidationError(
                'No account found, please try again with different email ID.')

        # self.create(user)
        uid = encode_uid(user.pk)
        token = default_token_generator.make_token(user)
        response['token'] = token
        response['uid'] = uid
        return Response(response, status=status.HTTP_200_OK)

    # def create(self, user):
    #     reset_request = PasswordReset.objects.filter(user=user).first()
    #     if reset_request:
    #         logger.debug('removed previous request')
    #         reset_request.delete()
    #     return PasswordReset.objects.create(user=user)


class ResetPasswordAPIView(APIView):
    # def get(self, request):

    #     token = request.query_params.get('token',None)
    #     if not token :
    #         raise ValidationError('Invalid reset request')

    #     reset_token = PasswordReset.objects.filter(reset_token=token).first()
    #     if not reset_token:
    #         raise ValidationError('Invalid reset token')
    #     if reset_token.valid_till < timezone.now():
    #         raise ValidationError('Expired reset token')
    #     reset_token.usable = True
    #     reset_token.save()

    #     response = {'status': 'success'}
    #     return Response(response, status=status.HTTP_200_OK)


    def post(self, request):

        data = request.data.get('user', {})
        if not data:
            raise ValidationError('Invalid request')

        uid = data.get('uid', None)
        token = data.get('token', None)
        password = data.get('password', None)
        if not token or not password or not uid:
            raise ValidationError('Invalid reset request, missing or invalid params')


        try:
            uid = decode_uid(uid)
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            raise ValidationError('Invalid reset request, user not found')

        is_token_valid = default_token_generator.check_token(user, token)
        if is_token_valid:
            user.set_password(password)
            user.password_last_updated_at = timezone.now()
            user.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        else:
            raise ValidationError('Invalid reset request, Please request a new password reset')



        # reset_token = PasswordReset.objects.filter(reset_token=token).first()
        # if not reset_token:
        #     raise ValidationError('Invalid reset token')
        # # TODO: check for usable field
        # reset_token.user.set_password(password)
        # reset_token.user.password_last_updated_at = timezone.now()
        # reset_token.user.save()
        # reset_token.delete()
        # return Response({'status': 'success'}, status=status.HTTP_200_OK)




