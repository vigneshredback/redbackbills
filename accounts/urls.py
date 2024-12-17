from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns =[
    path('register/',views.register_view,name='register'),
    path('verify-email/<int:user_id>',views.verify_email_view,name='verify_email'),
    path('login/',views.login_view,name='login'),
    # path('logout/',views.logout_view,name='logout'),
    path('password-reset/', views.password_reset_request_view, name='password_reset_request'),
    path('password-reset/verify/', views.password_reset_verify_view, name='password_reset_verify'),
    path('password-reset/form/<int:user_id>/', views.password_reset_form_view, name='password_reset_form'),
    path('logout/', views.logout_view, name='logout'),
]

