import jwt
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files.base import File
from django.core.mail import BadHeaderError, EmailMessage, send_mail
from django.db.models import Q, query
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import (DjangoUnicodeDecodeError, force_bytes,
                                    force_str, smart_bytes,
                                    smart_str)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.cache import never_cache
from django.views.generic import CreateView
from rest_framework import generics, serializers, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import (TokenObtainPairView,
                                            TokenRefreshView)


from accounts.models import (
    Administrator, Worker, User
)
from accounts.permissions import (
    IsAdministrator, ISWorker)
from accounts.serializers import (
    LoginSerializer, UserSerializer,
    WorkerRegistrationSerializer, ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer, AdministratorProfileSerializer,
    WorkerProfileSerializer)
from accounts.sendMails import (
    send_activation_mail, send_password_reset_mail)

class LoginViewSet(ModelViewSet, TokenObtainPairView):
    """"
    User Login API View
    """
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    http_method_names = ['post']


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        return Response(serializer.validated_data,
                        status=status.HTTP_200_OK)

class RegistrationViewSet(ModelViewSet, TokenObtainPairView):
    """
    Worker Registration API View
    """
    serializer_class = WorkerRegistrationSerializer
    permission_classes = (AllowAny,)
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exceptions=True)
        user = serializer.save()
        user_data = serializer.data
        send_activation_mail(user_data, request)
        refresh = RefreshToken.for_user(user)
        res = {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }
        return Response({
            "user":serializer.data,
            "refresh": res["access"],
            "token": res["access"]
        }, status=status.HTTP_201_CREATED)

class RefreshViewSet(viewsets.ViewSet, TokenRefreshView):
    """
    User Refresh Token API View
    """
    permission_classes = (AllowAny,)
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

def VerifyMail(request):
    token = request.GET.get('token')
    try:
        payload = jwt.decode(
            token,
            settings.SECRE_KEY,
            algorithms='HS256',
        )
        user = User.objects.get(
            id=payload['user_id']
        )
        if not user.is_active:
            user.is_active = True
            user.save()
            messages.success(request,
                            "Account was successfuly veirified.")
        else:
            messages.info(request,
                            """
                            Your account has already been activated.
                            You can now login
                            """)
    except jwt.ExpiredSignatureError as identifier:
        messages.warning(request, 
                        "The Activation Link has Expired. Please Request another one.")
    except jwt.exceptions.DecodeError as identifier:
        messages.warning(request, "Invalid Activation Link!")
    
    context = {}
    return render(request, "accounts/verify.html", context)

# Password Reset
class RequestPasswordResetEmail(ModelViewSet):
    """
    Password Reset API View
    The user inputs the email for password reset
    """
    serializer_class = ResetPasswordEmailRequestSerializer
    permission_classes = (AllowAny,)
    http_method_names = ['post',]

    def create(self, request, *args, **kwargs):
        self.get_serializer(data=request.data)
        email = request.data['email']
        if User.objects.get(email=email):
            user = User.objects.get(email=email)
            if user.is_active:
                send_password_reset_mail(user, request)
            return Response(
                {"Success": "We have emailed you a link to reset your password"},
                status = status.HTTP_200_OK
            )
        return Response({"Success": "Password Reset link was sent to your email."})

def PasswordResetTokenCheck(request, uidb64, token):
    try:
        id = smart_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            messages.info(
                request,
                "Password Reset Link is no longer valid. Please request a new one.")
    except DjangoUnicodeDecodeError as identifier:
        if not PasswordResetTokenGenerator().check_token(user, token):
            messages.info(
                request,
                "Password is no longer valid, please request a new one.")
    context = {
        "uidb64": uidb64,
        "token": token,
    }
    return render(request, "accounts/password_reset.html", context)

class SetNewPasswordAPIView(ModelViewSet):
    """
    Set a new Password API View for your account
    """
    serializer_class = SetNewPasswordSerializer
    permission_classes = (AllowAny,)
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            password = request.data['password']
            password_confirmation = request.data['password_confirmation']
            token = request.data['token']
            uidb64 = request.data['uidb64']
            if (password  and password_confirmation
                and password_confirmation != password_confirmation):
                raise serializers.ValidationError(
                    {"Error": ("Passwords don\'t match")}
                )
            else:
                id = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(id=id)
                if not PasswordResetTokenGenerator().check_token(user, token):
                    raise AuthenticationFailed(
                        "The Reset Link is Invalid",
                        401
                    )
                else:
                    user.set_password(password)
                    user.save()
                    return Response(
                        {"success": "Password reset successful"},
                        status = status.HTTP_201_CREATED)
        except Exception as e:
            raise AuthenticationFailed(
                "The Reset Link is Invalid", 401)
        return Response(serializer.data)

#Profile
class WorkerProfileAPIView(ModelViewSet):
    """
    Worker Profile API View
    """
    serializer_class = WorkerProfileSerializer
    permission_classes = (IsAuthenticated, ISWorker)
    http_method_names = ["get", "put"]

    def get_queryset(self):
        user = self.request.user
        workerQuery = Worker.objects.filter(
            Q(user=user)
        )
        return workerQuery
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, many=False)
        return Response(serializer.data,
                        status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        userSerializer = UserSerializer(
            request.user, data=request.data["user"]
        )
        userSerializer.is_valid(raise_exception=True)
        userSerializer.save()
        return Response(
            serializer.sata, status=status.HTTP_202_ACCEPTED
        )

class AdministratorProfileAPIView(ModelViewSet):
    """
    Administrator Profile API View
    """
    serializer_class = AdministratorProfileSerializer
    permission_classes = [IsAuthenticated, IsAdministrator]
    http_method_names = ["get", "put"]

    def get_queryset(self):
        user = self.request.user
        adminQuery = Administrator.objects.filter(
            Q(user=user)
        )
        return adminQuery
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, many=False)
        return Response(serializer.data,
                        status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        userSerializer = UserSerializer(
            request.user, data=request.data["user"]
        )
        userSerializer.is_valid(raise_exception=True)
        userSerializer.save()
        return Response(
            serializer.data, status=status.HTTP_202_ACCEPTED
        )