from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Item(models.Model):
    title = models.CharField(max_length=100)
    password = models.TextField(blank=True)
    key = models.CharField(max_length=500)
    for_org = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    def __str__(self):
        return self.title


class Organization(models.Model):  
    title = models.CharField(max_length=100)
    password = models.ManyToManyField(Item, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    def __str__(self):
        return self.title


class Member(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="member")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    edit_permission = models.BooleanField(default=False)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="added_by", blank=True)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    class Meta:
        unique_together = ('user', 'organization')
    



class Share(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user")
    edit_permission = models.BooleanField(default=False)
    item = models.ForeignKey(Item,on_delete=models.CASCADE)
    shared_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="shared_user", blank=True)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)






    