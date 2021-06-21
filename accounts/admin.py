from django.contrib import admin

from .models import User,BlackList,PasswordReset

admin.site.register(User)
admin.site.register(BlackList)
admin.site.register(PasswordReset)