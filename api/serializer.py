from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import *
from rest_framework import exceptions, response
from django.contrib.auth import authenticate
from rest_framework.validators import UniqueValidator
from . import models
from cryptography.fernet import Fernet 





class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'password',
            'email',
            'first_name',
        )
        extra_kwargs = {
            'password': {'write_only': True}, 'email':{'required':True},'first_name':{'required':True},
            "username":{"required":True,}
        }

    def create(self, validated_data):
        validated_data["username"] = validated_data["email"]
        user = User.objects.create_user(**validated_data)
        return user



class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')
        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    data["user"] = user

                else:
                    msg = "Account deactivated"
                    raise exceptions.ValidationError(msg)
            else:
                try:
                    userdata = User.objects.get(email=username)
                    user = authenticate(username=userdata.username, password=password)
                    if user.is_active:
                        data["user"] = user

                    else:
                        msg = "Account deactivated"
                        raise exceptions.ValidationError(msg)
                except Exception as e:
                    msg = "Wrong Credinails"
                    raise exceptions.ValidationError(msg)
        else:
            msg = "Must provide user name and password"
            raise exceptions.ValidationError(msg)
        return data


class ItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Item
        fields = ('id','title','password')


class GetItemsSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField("getpass")
    can_edit = serializers.SerializerMethodField("checkedit")
    def getpass(self, data):
        fernet = Fernet(data.key.encode('utf-8')) 
        passw = fernet.decrypt(data.password.encode()).decode()
        return passw
    
    def checkedit(self, data):
        print(self.context["user"])
        if data.created_by.id == self.context["user"]:
            return True
        else:
            try:
                share = models.Share.objects.get(user=self.context["user"],password_id=data.id)
                return True
            except:
                return False
    class Meta:
        model = models.Item
        fields = ('id','title','password',"can_edit")

class GetOrganizationSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField("getuser")
    password = serializers.SerializerMethodField("getpass")
    can_edit = serializers.SerializerMethodField("canedit")

    def getuser(self,data):
        return {'name':data.created_by.first_name, "email": data.created_by.email}

    def getpass(self, data):
        ser = GetItemsSerializer(data.password,many=True,context={"user":self.context["user"]})
        return ser.data
    
    def canedit(self, data):
        if data.created_by.id == self.context["user"]:
            return True
        else:
            try:
                member = models.Member.objects.get(organization=data,user_id=self.context["user"])
                return member.edit_permission
            except:
                return False

    class Meta:
        model = models.Organization
        fields = ('id',"created_by","title","password","can_edit")
        depth = 0



class GetOrganizationSerializer2(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField("getuser")
    password = serializers.SerializerMethodField("getpass")

    def getuser(self,data):
        return {'name':data.created_by.first_name, "email": data.created_by.email}

    def getpass(self, data):
        ser = ItemsSerializer(data.password,many=True)
        return ser.data
    

    class Meta:
        model = models.Organization
        fields = ('id',"created_by","title","password",)
        depth = 0



class OrganizationSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Organization
        fields = ('id', 'title')



class MemberSerializer(serializers.ModelSerializer):
    organization = GetOrganizationSerializer2()
    user = UserSerializer()

    class Meta:
        model = models.Member
        fields = "__all__"


class AddMemberSerializer(serializers.ModelSerializer):
    user = serializers.CharField()
    class Meta:
        model = models.Member
        fields = "__all__"
        extra_kwargs = {
            'added_by': {
                'validators': []
            }
        }


class ShareSerializer(serializers.ModelSerializer):
    user = serializers.CharField()
    class Meta:
        model = models.Share
        fields = "__all__"