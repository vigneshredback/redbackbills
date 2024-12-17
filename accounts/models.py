from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now
from datetime import timedelta

class EmailVerification(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False)

    def is_expired(self):
        # Token expires in 10 minutes
        return now() > self.created_at + timedelta(minutes=10)

    def __str__(self):
        return f"{self.user.username} - {'Verified' if self.verified else 'Not Verified'}"


class PasswordResetToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        # Token expires in 10 minutes
        expiration_time = self.created_at + timedelta(minutes=10)
        return self.created_at > expiration_time  # Compare with timezone-aware `now()`

    def __str__(self):
        return f"{self.user.username} - Token {self.token}"
