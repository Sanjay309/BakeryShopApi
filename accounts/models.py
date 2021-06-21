import uuid
from datetime import datetime, timedelta

import jwt
from django.conf import settings
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager,
                                        PermissionsMixin)
from django.db import models

from django.utils import timezone
from django.conf import settings
from rest_framework.exceptions import ValidationError
from phonenumber_field.modelfields import PhoneNumberField
import logging
from django.contrib.auth.tokens import default_token_generator

logger = logging.getLogger(__name__)


class TimestampedModel(models.Model):
    # A timestamp representing when this object was created.
    created_at = models.DateTimeField(auto_now_add=True)

    # A timestamp reprensenting when this object was last updated.
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

        # By default, any model that inherits from `TimestampedModel` should
        # be ordered in reverse-chronological order. We can override this on a
        # per-model basis as needed, but reverse-chronological is a good
        # default ordering for most models.
        ordering = ['-created_at', '-updated_at']



class UserManager(BaseUserManager):

    def validate_email(self,email):    
        if not email:
            raise ValidationError('Users must have an email address')
        

    def create_user(self, email, phone=None, password=None, **kwargs):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        self.validate_email(email)

        user = self.model(
            email=self.normalize_email(email),
            phone=phone,
            **kwargs
        )

        user.set_password(password)
        user.save()
        return user

    
        

    def create_superuser(self, email, phone=None, password=None, **kwargs):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(
            email,
            password=password,
            phone=phone,
            **kwargs
        )
        user.is_superuser = True
        user.is_admin = True
        user.is_active=True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin, TimestampedModel):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    # phone = models.CharField(max_length=15,null=True,blank=True)

    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)

    phone = PhoneNumberField(null=True,blank=True)
    
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    password_last_updated_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return str(self.email)

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def token(self):
        """
        Allows us to get a user's token by calling `user.token` instead of
        `user.generate_jwt_token().
        """
        return self._generate_jwt_token()

    def get_full_name(self):
      """
      This method is required by Django for things like handling emails.
      Typically, this would be the user's first and last name. Since we do
      not store the user's real name, we return their username instead.
      """
      return self.first_name + " " +self.last_name

    def get_short_name(self):
        """
        This method is required by Django for things like handling emails.
        Typically, this would be the user's first name. Since we do not store
        the user's real name, we return their username instead.
        """
        return self.first_name

    def _generate_jwt_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 60 days into the future.
        """
        dt = datetime.now() + timedelta(days=settings.JWT_EXPIRES)

        token = jwt.encode({
            'id': self.pk,
            'exp': int(dt.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS256')

        return token.decode('utf-8')
    



class BlackList(models.Model):
    token = models.CharField(db_index=True, max_length=255, unique=True,primary_key=True)


def get_password_reset_valid_till():
    return timezone.now() + timedelta(minutes=settings.PASSWORD_RESET_LIFETIME)


class PasswordReset(TimestampedModel):
    user = models.OneToOneField(
        'accounts.User', on_delete=models.CASCADE,related_name='reset_token'
    )
    reset_token = models.UUIDField(default=uuid.uuid4)
    valid_till = models.DateTimeField(default=get_password_reset_valid_till)
    usable = models.BooleanField(default=False)



