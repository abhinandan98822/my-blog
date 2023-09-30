from django.urls import path
from blog.views import *

urlpatterns = [
    path('',Index,name='index'),
    path('sign-up/',SignUp,name='register'),
    path('login/',Login,name='login'),
    path('forgot-password/',Forgot_Password,name='forgot_password'),
    path('reset-password/<str:uid>/<str:token>/',Reset_Password,name='reset_password'),
    path('dashboard/',BlogListView,name='bloglist'),
    path('blog/<int:blog_id>/', BlogDetailView, name='blogdetail'),
    path('blog/<int:blog_id>/comment/', add_comment, name='add_comment'),
    path('comment/<int:comment_id>/like/', like_comment, name='like_comment'),
    path('blog/<int:blog_id>/share/', share_blog, name='share_blog'),
    path('like_comment/<int:comment_id>/', like_comment, name='like_comment'),
]