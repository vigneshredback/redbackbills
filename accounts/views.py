import random
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib import messages
from .forms import RegisterForm, VerificationForm
from .models import EmailVerification,PasswordResetToken
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages



def register_view(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validate passwords
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        # Check if email is already in use
        if User.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists.")
            return redirect('register')

        # Create the user with email as username
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=email,  # Use email as the username
            is_active=False  # User is inactive until email verification
        )
        user.set_password(password)  # Hash the password
        user.save()

        # Generate email verification code
        verification_code = f"{random.randint(100000, 999999)}"
        EmailVerification.objects.create(user=user, code=verification_code)

        # Send verification email
        send_mail(
            'Verify Your Email',
            f'Your verification code is {verification_code}. It expires in 10 minutes.',
            'no-reply@example.com',  # Replace with your email
            [email],
            fail_silently=False,
        )

        messages.success(request, "Registration successful! Please check your email for the verification code.")
        return redirect('verify_email', user_id=user.id)

    return render(request, 'accounts_pages/register.html')

def verify_email_view(request, user_id):
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('register')

    if request.method == 'POST':
        code = request.POST.get('code')
        try:
            verification = EmailVerification.objects.get(user=user, code=code)
            if verification.is_expired():
                messages.error(request, "The verification code has expired. Please register again.")
                user.delete()  # Remove the unverified user
                return redirect('register')

            # Mark email as verified and activate user
            verification.verified = True
            verification.save()
            user.is_active = True
            user.save()

            login(request, user)
            messages.success(request, "Email verified successfully! You are now logged in.")
            return redirect('index')
        except EmailVerification.DoesNotExist:
            messages.error(request, "Invalid verification code.")
    form = VerificationForm()
    return render(request, 'accounts_pages/verify_email.html', {'user': user, 'form': form})

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')  # Collect email from form
        password = request.POST.get('password')  # Collect password from form

        # Authenticate using email as username
        user = authenticate(request, username=email, password=password)

        if user:
            # Check if user is active
            if not user.is_active:
                messages.error(request, "Your account is inactive. Please verify your email.")
                return redirect('login')

            # Check if email is verified
            email_verification = EmailVerification.objects.filter(user=user).first()
            if email_verification and not email_verification.verified:
                messages.error(request, "Your email is not verified. Please verify it.")
                return redirect('verify_email', user_id=user.id)

            # Log the user in
            login(request, user)
            messages.success(request, f"Welcome back, {user.first_name}!")
            return redirect('index')  # Redirect to your homepage or dashboard

        else:
            messages.error(request, "Invalid email or password.")
            return redirect('login')

    return render(request, 'accounts_pages/login.html')
# Step 1: Request Password Reset
def password_reset_request_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')  # Get email from the form
        try:
            user = User.objects.get(email=email)  # Fetch the user by email
            token = f"{random.randint(100000, 999999)}"  # Generate a 6-digit token
            PasswordResetToken.objects.update_or_create(user=user, defaults={'token': token})

            # Send the reset token via email
            send_mail(
                'Password Reset Request',
                f'Your password reset code is {token}. It expires in 10 minutes.',
                'no-reply@example.com',  # Replace with your email
                [email],
                fail_silently=False,
            )
            messages.success(request, 'A password reset code has been sent to your email.')
            return redirect('password_reset_verify')  # Redirect to token verification page
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email.')  # Email not registered
    return render(request, 'accounts_pages/password_reset_request.html')

# Step 2: Verify OTP
def password_reset_verify_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')  # Collect email
        token = request.POST.get('token')  # Collect token
        try:
            user = User.objects.get(email=email)  # Get user by email
            reset_token = PasswordResetToken.objects.get(user=user, token=token)
            
            print("Token creation time:", reset_token.created_at)
            # print("Current time:", now())
            print("Token expiration status:", reset_token.is_expired())

            if reset_token.is_expired():
                messages.error(request, 'The reset code has expired. Please try again.')
                return redirect('password_reset_request')

            messages.success(request, 'Token verified successfully. Please reset your password.')
            return redirect('password_reset_form', user_id=user.id)
        except (User.DoesNotExist, PasswordResetToken.DoesNotExist):
            messages.error(request, 'Invalid token or email.')
    return render(request, 'accounts_pages/password_reset_verify.html')

# Step 3: Reset Password
def password_reset_form_view(request, user_id):
    try:
        user = User.objects.get(pk=user_id)  # Get the user by ID
    except User.DoesNotExist:
        messages.error(request, "Invalid user.")
        return redirect('password_reset_request')

    if request.method == 'POST':
        password = request.POST.get('password')  # New password
        confirm_password = request.POST.get('confirm_password')  # Confirmation password

        print("Received password:", password)
        print("Confirm password:", confirm_password)

        if password != confirm_password:  # Check if passwords match
            messages.error(request, 'Passwords do not match.')
            return redirect('password_reset_form', user_id=user.id)

        try:
            user.set_password(password)  # Properly hash and save the new password
            user.save()
            print("Password reset successfully for user:", user.username)
        except Exception as e:
            print("Error while resetting password:", e)
            messages.error(request, "An error occurred while resetting your password.")
            return redirect('password_reset_form', user_id=user.id)

        PasswordResetToken.objects.filter(user=user).delete()  # Clean up token
        messages.success(request, 'Your password has been reset successfully. Please log in.')
        return redirect('login')  # Redirect to login page

    return render(request, 'accounts_pages/password_reset_form.html')


def logout_view(request):
    logout(request)  # Logs out the user
    messages.success(request, "You have been logged out successfully.")  # Success message
    return redirect('login')  # Redirect to login page
