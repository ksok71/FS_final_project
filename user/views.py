from contextlib import redirect_stderr
from django.contrib.auth import get_user_model, login, logout, authenticate
from user.models import User
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponseRedirect
from django.shortcuts import render
from .forms import LoginForm, RegisterForm

#imported by KSOK
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, PasswordResetForm
from django.contrib.auth.hashers import make_password, check_password
from django.http.response import JsonResponse
from django.shortcuts import redirect
from django.contrib.auth.mixins import LoginRequiredMixin


User = get_user_model()


def index(request):
    return render(request, "index.html")


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect("/login")
    else:
        logout(request)
        form = RegisterForm()
    return render(request, "register.html", {"form": form})


def login_view(request):
    # TODO: 1. /login로 접근하면 로그인 페이지를 통해 로그인이 되게 해주세요
    # TODO: 2. login 할 때 form을 활용해주세요		
    is_ok = False	
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            raw_password = form.cleaned_data.get("password")
            remember_me = form.cleaned_data.get("remember_me")
            msg = "올바른 유저ID와 패스워드를 입력하세요."
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                msg = "올바른 유저ID와 패스워드를 입력하세요."
            else: # username 및 password 인증
                if check_password(raw_password, user.password):
                    msg = None
                    login(request, user)
                    is_ok = True
                    request.session["remember_me"] = remember_me
                    request.session['user'] = user.id

                    return render(request, "index.html", {"username": username})

                    # if not remember_me:
                    #     request.session.set_expiry(0)
    else:
        msg = None
        form = LoginForm()
    for visible in form.visible_fields():
        visible.field.widget.attrs["placeholder"] = "유저ID" if visible.name == "username" else "패스워드"
        visible.field.widget.attrs["class"] = "form-control"
    return render(request, "login.html", {"form": form, "msg": msg, "is_ok": is_ok})


def logout_view(request):
    # TODO: 3. /logout url을 입력하면 로그아웃 후 / 경로로 이동시켜주세요		
    logout(request)				
    return redirect("/")


# TODO: 8. user 목록은 로그인 유저만 접근 가능하게 해주세요
@login_required
def user_list_view(request):
    # TODO: 7. /users 에 user 목록을 출력해주세요
    # TODO: 9. user 목록은 pagination이 되게 해주세요
    page = int(request.GET.get("page", 1))
    users = User.objects.all().order_by("id")
    
    paginator = Paginator(users, 10)
    users = paginator.get_page(page)

    return render(request, "users.html", {"users": users})