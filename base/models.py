from django.contrib.auth.models import AbstractUser
from django.db import models
import string
import random


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customUser_user_set',  # Add related_name argument
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        verbose_name='groups',
    )
    user_permissions=models.ManyToManyField(
        'auth.Permission',
        related_name='customUser_user_set',  # Add related_name argument
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )	


    def __str__(self):
        return f'{self.username}'
    




class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name
    



def generate_alphanumeric_code(length=8):
    """Generates a random alphanumeric code."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

class Employees(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE,related_name='employee_data')
    employee_id = models.CharField(max_length=100, unique=True,null=True)
    department = models.ForeignKey(Department, related_name='employees', on_delete=models.SET_NULL, null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    address = models.TextField(blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    is_supervisor = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.employee_id:
            self.employee_id = generate_alphanumeric_code()
        super(Employees, self).save(*args, **kwargs)

    def __str__(self):
        return self.user.username