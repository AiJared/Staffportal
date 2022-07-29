from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import validators
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.utils.translation import gettext as _
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class TrackingModel(models.Model):
    date_created = models.DateTimeField(_("date created"), auto_now_add=True)
    date_updated = models.DateTimeField(_("date updated"), auto_now=True)

    class Meta:
        abstract = True

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None,
                    is_active=True, is_admin=False, is_staff=False
                    ):
        if email is None:
            raise ValueError("User must have an email!")
        if username is None:
            raise ValueError("User must have a username!")
        if password is None:
            raise ValueError("User must have a password!")
        
        user_obj = self.model(
            email = self.normalize_email(email),
            username=username
        )

        user_obj.set_password(password)
        user_obj.is_active = is_active
        user_obj.is_admin = is_admin
        user_obj.is_staff = is_staff

        user_obj.save(using=self._db)

        return user_obj
    
    def create_staff(self, email, username, password=None):
        user = self.create_user(
            email, username, password=password,
            is_active=True,
            is_admin=False,
            is_staff=False)
        
        return user
    
    def create_superuser(self, email, username, password=None):
        user = self.create_user(
            email, username, password=password,
            is_active=True,
            is_admin=True,
            is_staff=True
        )

        return user

class User(AbstractBaseUser, TrackingModel):
    role_choices  = (
        ('administrator', 'administrator'),
        ('worker', 'worker')
    )

    full_name = models.CharField(_('full name'), max_length=200, blank=False, null=False)
    username = models.CharField(_("username"), max_length=70, unique=True)
    email = models.EmailField(_("email"), max_length=250, blank=False, null=False, unique=True)
    phone = PhoneNumberField(_("phone"), unique=True, blank=False, null=False)
    is_admin = models.BooleanField(_("admin"), default=False)
    is_active = models.BooleanField(_("active"), default=True)
    is_staff = models.BooleanField(_("staff"), default=False)
    role = models.CharField(_("role"), max_length=50, choices=role_choices)
    timestamp = models.DateTimeField(_('timeatamp'), auto_now_add=True)

    def get_queryset(self):
        users = User.objects.all()

    def __str__(self):
        return self.username

    object = CustomUserManager
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'password']

    def has_perms(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
    
    @property
    def admin(self):
        return self.admin

    @property
    def staff(self):
        return self.staff

    @property
    def active(self):
        return self.active

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(_("profile picture"), upload_to='profile_pictures')
    bio = models.TextField(_('bio'), blank=True, null=True)

    class Meta:
        abstract = True
        ordering = ["-id"]

    def __str__(self):
        return self.user.username

class Administrator(Profile):
    first_name = models.CharField(_("first name"), max_length=50, blank=False, null=False)
    last_name = models.CharField(_("last name"), max_length=70, blank=False, null=False)
    county = models.CharField(_("county"),
                                max_length=80, blank=True, null=True)
    town = models.CharField(_("town"),
                                max_length=80, blank=True, null=True)
    estate = models.CharField(_("estate"),
                                max_length=90, blank=True, null=False)
    
    def __str__(self):
        return self.user.username

class Worker(Profile):
    first_name = models.CharField(_("first name"),
                                    max_length=200, blank=False, null=False)
    last_name = models.CharField(_("last name"),
                                    max_length=200, blank=False, null=False)
    company = models.CharField(_("company"),
                                max_length=250, blank=True, null=True)
    department = models.CharField(_("department"), 
                                    max_length=250, blank=True, null=True)
    year = models.DateTimeField(_("year"),
                                    auto_now_add=True)
    county = models.CharField(_("county"), 
                                max_length=100, blank=True, null=True)
    town = models.CharField(_("town"), 
                                max_length=100, blank=True, null=True)
    address = models.CharField(_("address"), 
                                max_length=250, blank=True, null=True)
    postal_code = models.CharField(_("postal code"),
                                    max_length=70, blank=True, null=True)
    
    def __str__(self):
        return self.user.username

    class Meta:
        ordering = ["-id"]