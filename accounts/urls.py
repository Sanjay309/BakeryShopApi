from django.urls import path

from .views import (
    LoginAPIView, RegistrationAPIView, UserRetrieveUpdateAPIView, LogoutAPIView, ForgotPasswordAPIView, ResetPasswordAPIView
)
from .views import AccountsTokenObtainPairView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('user/token/', AccountsTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('user/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # cross this bridge when its required
    path('user/', UserRetrieveUpdateAPIView.as_view()),
    path('users/', RegistrationAPIView.as_view()),
    path('users/login/', LoginAPIView.as_view()),


    path('users/logout/', LogoutAPIView.as_view()),
    path('users/forgot-password/', ForgotPasswordAPIView.as_view()),
    path('users/reset-password/', ResetPasswordAPIView.as_view()),
    
]
