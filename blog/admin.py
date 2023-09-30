from django.contrib import admin
from blog.models import MyUser,Blog,Comment,Like,Share
# Register your models here.
admin.site.register(MyUser)
admin.site.register(Blog)
admin.site.register(Comment)
admin.site.register(Like)
admin.site.register(Share)