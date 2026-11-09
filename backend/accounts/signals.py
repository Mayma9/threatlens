"""Feedback messages on login and logout, shown as toasts by accounts/js/alerts.js."""

from django.contrib import messages
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver


@receiver(user_logged_in)
def welcome_message(sender, request, user, **kwargs):
    if request is not None:
        name = user.get_full_name() or user.username
        messages.success(request, f"Welcome back, {name}.", fail_silently=True)


@receiver(user_logged_out)
def logout_message(sender, request, user, **kwargs):
    if request is not None:
        messages.info(request, "You are logged out.", fail_silently=True)
