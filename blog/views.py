from django.shortcuts import render,redirect
from blog.models import MyUser
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.contrib.auth import logout
from django.http import HttpResponse, JsonResponse
import re
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404
from .models import Blog,Comment,Like,Share
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate,login
from django.core.exceptions import ValidationError
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator

# Create your views here.
def Index(request):
    return render(request, 'index.html')

def SignUp(request):
    if request.method == 'POST':
        username=request.POST.get('username')
        email=request.POST.get('email')
        password=request.POST.get('password')
        confirm_password=request.POST.get('confirm-password')
        if len(password) < 8:
            return render(request, 'signup.html', {'error_message': 'Password must be at least 8 characters long'})
        
        if password != confirm_password:
            return render(request, 'signup.html', {'error_message': 'Passwords do not match'})

        if not re.search(r'[A-Z]', password):
            return render(request, 'signup.html', {'error_message': 'Password must contain at least one capital letter'})  
              
        password=make_password(password)
        user=MyUser(username=username,email=email,password=password)
        user.save()
        subject="Registered Successfully"
        message=f"Hello, {user} you are successfully registered,Enjoy the Blog"
        email_from=settings.EMAIL_HOST_USER
        recipient_list=[user.email,]
        email_message = render_to_string('register_success_email.html', {
            'user': user,
        })

        send_mail(subject,message,email_from,recipient_list,html_message=email_message)
        return redirect('login')
    return render(request, 'signup.html')


def Login(request):
    if request.method == 'POST':
        email=request.POST.get('email')
        password=request.POST.get('password') 
        user = authenticate(email=email, password=password) 
        if user is not None:
            login(request,user)
            return redirect('bloglist')
        else:
            return HttpResponse("invalid credential")
    return render(request, 'login.html')


def get_user_from_uid_and_token(uidb64, token):
    """
    Get the user from uidb64 and token.This function is created to decode the url of forgot password
    """
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
        if default_token_generator.check_token(user, token):
            return user
        else:
            raise ValidationError("Invalid token")
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        raise ValidationError("Invalid user or token")

def Forgot_Password(request):
    if request.method=="POST":
        email=request.POST.get('email')
        user=MyUser.objects.filter(email=email).first()
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = "http://127.0.0.1:8000/reset-password/" + uid + '/' + token
            subject="forgot password"
            message=f"Hello, {user} you are forgot your password"
            email_from=settings.EMAIL_HOST_USER
            recipient_list=[user.email,]
            email_message = render_to_string('forgot_password_email.html', {
                'user': user,
                'reset_link': link,
            })

            send_mail(subject,message,email_from,recipient_list,html_message=email_message)
            return render(request,'email_send.html')
        #send mail functionality
        else:
            return ValidationError("user Does not exist")
  
    return render(request, 'forgot_password.html')

def Reset_Password(request,uid,token):
    if request.method == 'POST':
        new_password = request.POST.get('password')
        confirm_new_password=request.POST.get('ConfirmPassword')
        if len(new_password) < 8:
            return render(request, 'reset_password.html', {'error_message': 'Password must be at least 8 characters long'})
        
        if new_password != confirm_new_password:
            return render(request, 'reset_password.html', {'error_message': 'Passwords do not match'})

        if not re.search(r'[A-Z]', new_password):
            return render(request, 'reset_password.html', {'error_message': 'Password must contain at least one capital letter'}) 

        user = get_user_from_uid_and_token(uid, token)    
        user.set_password(new_password)
        user.save()
        return redirect('login')

    return render(request, 'reset_password.html')       




def BlogListView(request):
    blogs = Blog.objects.all()
    paginator = Paginator(blogs, 5)  # Show 5 blogs per page

    page = request.GET.get('page')
    try:
        blogs = paginator.page(page)
    except PageNotAnInteger:
        blogs = paginator.page(1)
    except EmptyPage:
        blogs = paginator.page(paginator.num_pages)

    return render(request, 'blog_list.html', {'blogs': blogs})

def BlogDetailView(request, blog_id):
    blog = get_object_or_404(Blog, pk=blog_id)
    comments = Comment.objects.filter(blog=blog)
    return render(request, 'blog_detail.html', {'blog': blog, 'comments': comments})

def add_comment(request, blog_id):
    if request.method == 'POST':
        blog = get_object_or_404(Blog, pk=blog_id)
        text = request.POST.get('text')
        author = request.user
        comment = Comment.objects.create(blog=blog, author=author, text=text)
        comment.save()
        return JsonResponse({
            'message': 'Comment added successfully!',
            'comment_id': comment.id,
            'author': comment.author.username,
        })
    return JsonResponse({'message': 'Invalid request method'}, status=400)
    # return HttpResponse(status=400)


def like_comment(request, comment_id):
    if request.method == 'POST':
        comment = get_object_or_404(Comment, pk=comment_id)
        user = request.user

        # Check if the user has already liked the comment
        existing_like = Like.objects.filter(comment=comment, user=user).first()

        if existing_like:
            # If the user has already liked the comment, remove the like
            existing_like.delete()
            message = 'Like removed successfully!'
        else:
            # If the user hasn't liked the comment, create a new like
            like = Like(comment=comment, user=user)
            like.save()
            message = 'Comment liked successfully!'

        return JsonResponse({'message': message})
    return JsonResponse({'message': 'Invalid request'})

def share_blog(request, blog_id):
    # Get the blog object
    blog = get_object_or_404(Blog, pk=blog_id)

    if request.method == 'POST':
        # Get recipient's email and message from the form
        shared_email = request.POST.get('shared_email')
        message = request.POST.get('message')
        
        # Create a Share object to record the sharing and save it to the database
        share = Share(blog=blog, email=shared_email, message=message)
        share.save()

        # Create the link to the shared blog
        share_link = request.build_absolute_uri(blog.get_absolute_url())

        # Add logic here to send the email with the shared blog content and link
        # You can use Django's email functionality here
        subject = "Shared Blog"
        email_message = render_to_string('share_blog_email.html', {
            'blog': blog,
            'message': message,
            'share_link': share_link,  # Pass the share link to the email template
        })
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [shared_email, ]

        send_mail(subject, "", from_email, recipient_list, html_message=email_message)

        return redirect('blogdetail', blog_id=blog_id)  # Redirect back to the blog detail page after sharing

    return render(request, 'share_blog.html', {'blog': blog})