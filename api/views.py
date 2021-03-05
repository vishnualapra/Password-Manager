from django.contrib.auth.models import User
from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from . import serializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.response import Response
from django.contrib.auth import login, logout
from rest_framework.authtoken.views import Token
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework import status
from . import models
import json
from django.db.models import Q
from rest_framework.permissions import BasePermission
from cryptography.fernet import Fernet 
import codecs


class OrganizationPermssion(BasePermission):

    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        if view.action == 'retrieve':
            if obj.created_by.id == request.user.id:
                return True
            else:
                try:
                    org = models.Member.objects.get(user=request.user,organization=obj)
                    return True
                except:
                    return False
        
        return True


class MemberPermssion(BasePermission):

    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        if view.action == 'retrieve':
            if obj.added_by.id == request.user.id:
                return True
            else:
                return False
        elif view.action == 'create':
            try:
                org = models.Organization.objects.get(id=obj, created_by=request.user)
                return True
            except:
                return False

        return True


class PassPermssion(BasePermission):

    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        if view.action == 'retrieve':
            if obj.created_by.id == request.user.id:
                return True
            else:
                try:
                    share = models.Share.objects.get(user=request.user, item=obj)
                    return True
                except:
                    return False
        elif view.action == 'partial_update':
            if obj.created_by.id == request.user.id:
                return True
            else:
                try:
                    share = models.Share.objects.get(user=request.user, item=obj, edit_permission=True)
                    return True
                except:
                    if obj.for_org == True:
                        try:
                            org = models.Organization.objects.get(password=obj)
                            member = models.Member.objects.get(Organization=org,user=request.user,edit_permission=True)
                            return True
                        except:
                            return False
                    return False


        return True



class SharePermssion(BasePermission):

    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        if view.action == 'retrieve':
            if obj.shared_by.id == request.user.id:
                return True
            else:
                return False
        elif view.action == 'create':
            try:
                org = models.Item.objects.get(id=obj, created_by=request.user)
                return True
            except:
                return False

        return True



class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = serializer.UserSerializer


class LoginViewset(viewsets.ViewSet):
    serializer_class = serializer.LoginSerializer

    def create(self, request):
        msg = False
        ser = serializer.LoginSerializer(data=request.data)
        ser.is_valid(raise_exception=False)
        try:
            user = ser.validated_data["user"]
            userobj = User.objects.get(id=user.id)
            login(request, user)
            userdata = {}
            userdata['id'] = userobj.id
            userdata['username'] = userobj.username
            userdata['full_name'] = userobj.first_name
            userdata['email'] = userobj.email
            msg = True
            try:
                Token.objects.get(user=user).delete()
            except:
                pass
            token, created = Token.objects.get_or_create(user=user)
            dat = {'token': token.key, 'details': userdata,}
            stat = status.HTTP_200_OK
        except Exception as e:
        
            msg = False
            dat = str(e)
            stat = status.HTTP_400_BAD_REQUEST

        return Response({'success': msg, 'data': dat, 'errors': ser.errors}, status=stat)


class Organization(viewsets.ModelViewSet):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, OrganizationPermssion)
    queryset = models.Organization.objects.all()
    serializer_class = serializer.GetOrganizationSerializer

    def create(self, request, *args, **kwargs):
        msg = False
        ser = serializer.OrganizationSerializer(data=request.data)
        ser.is_valid()
        ser.validated_data["created_by"] = request.user
        try:
            ser.save()
            msg = True
            dat = ser.data
            stat = status.HTTP_200_OK
            errors = []
        except Exception as e:
            dat = []
            msg = False
            errors = ser.errors
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)

    def list(self, request):
        if 'created_by_me' in request.GET and request.GET['created_by_me'] == '1': 
            queryset = models.Organization.objects.filter(created_by=request.user)
        elif 'created_by_me' in request.GET and request.GET['created_by_me'] == '0':
            queryset = models.Member.objects.filter(user=request.user).values('organization_id')
            queryset = models.Organization.objects.filter(id__in=queryset)
            print(queryset,"***")
        else:
             queryset = models.Organization.objects.filter(Q(created_by=request.user) | Q(id__in=models.Member.objects.filter(user=request.user).values('organization_id')))

        ser = serializer.GetOrganizationSerializer(queryset, many=True,context={'user': request.user.id})
        return Response(ser.data)


    def retrieve(self, request, pk=None):
        queryset = models.Organization.objects.get(pk=pk)
        self.check_object_permissions(self.request, queryset)
        ser = serializer.GetOrganizationSerializer(queryset, many=False, context={'user': request.user.id})
        return Response(ser.data)
        


class Member(viewsets.ModelViewSet):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, MemberPermssion)
    queryset = models.Member.objects.all()
    serializer_class = serializer.AddMemberSerializer

    def list(self, request):
        if 'organization' in request.GET: 
            queryset = models.Member.objects.filter(added_by=request.user, organization=request.GET['organization'])
        else:
            queryset = models.Member.objects.filter(added_by=request.user)
        print(queryset)

        ser = serializer.MemberSerializer(queryset, many=True,context={'user': request.user.id})
        return Response(ser.data)

 
    def retrieve(self, request, pk=None):
        queryset = models.Item.objects.get(pk=pk)
        self.check_object_permissions(self.request, queryset)
        ser = serializer.MemberSerializer(queryset, many=False, context={'user': request.user.id})
        return Response(ser.data)


    def create(self, request, *args, **kwargs):
        msg = False
        ser = serializer.AddMemberSerializer(data=request.data)
        ser.is_valid()
        member = request.data["user"]
        self.check_object_permissions(self.request, request.data["organization"])
        try:
            member = User.objects.get(email=member)
            ser.validated_data["added_by"] = request.user
            ser.validated_data["user"] = member
            try:
                ser.save()
                msg = True
                dat = ser.data
                stat = status.HTTP_200_OK
                errors = []
            except Exception as e:
                dat = []
                msg = False
                errors = ser.errors
                stat = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            dat = []
            msg = False
            errors = {"user":"not found" + str(e)}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)


    def destroy(self, request, pk=None):
        msg = False
        try:
            queryset = models.Member.objects.get(pk=pk,added_by=request.user)
            queryset.delete()
            msg = True
            stat  = status.HTTP_200_OK
            dat = []
            errors = []
        except:
            dat = []
            msg = False
            errors = {"failed":"no member/permission"}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)




class Item(viewsets.ModelViewSet):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, PassPermssion)
    queryset = models.Item.objects.all()
    serializer_class = serializer.GetItemsSerializer

    def destroy(self, request, pk=None):
        msg = False
        try:
            queryset = models.Item.objects.get(pk=pk,created_by=request.user)
            queryset.delete()
            msg = True
            stat  = status.HTTP_200_OK
            dat = []
            errors = []
        except:
            dat = []
            msg = False
            errors = {"failed":"no member/permission"}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)


    def create(self, request, *args, **kwargs):
        msg = False
        ser = serializer.ItemsSerializer(data=request.data)
        ser.is_valid()
        org = None
        if "for_org" in request.data:
            for_org = request.data.get("for_org")
            try:
                org = models.Organization.objects.get(id=for_org,created_by=request.user)
            except:
                dat = []
                msg = False
                errors = {"error":"organization not found or no permission"}
                stat = status.HTTP_400_BAD_REQUEST
                return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)
        try:
            ser.validated_data["created_by"] = request.user
            key = Fernet.generate_key() 
            fernet = Fernet(key)
            encPass = fernet.encrypt(request.data["password"].encode()) 
            ser.validated_data["password"] =codecs.decode(encPass, 'UTF-8')
            ser.validated_data["key"] = codecs.decode(key, 'UTF-8')
            if org:
                ser.validated_data["for_org"] = 1
            try:
                ser.save()
                if org:
                    org.password.add(ser.data["id"])
                msg = True
                dat = ser.data["id"]
                stat = status.HTTP_200_OK
                errors = []
            except Exception as e:
                dat = []
                msg = False
                errors = ser.errors
                stat = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            dat = []
            msg = False
            errors = {"error":"field not found/error" + str(e)}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)


    def list(self, request):
        if 'filter' in request.GET: 
            if request.GET['filter'] == "all":
                queryset = models.Item.objects.filter(Q(created_by=request.user) | Q(id__in=models.Share.objects.filter(user=request.user).values('item_id')))
            elif request.GET['filter'] == "owner":
                 queryset = models.Item.objects.filter(created_by=request.user) 
            elif request.GET['filter'] == "share":
                 queryset = models.Item.objects.filter(id__in=models.Share.objects.filter(user=request.user).values('item_id'))
            else:
                 queryset = models.Item.objects.filter(Q(created_by=request.user) | Q(id__in=models.Share.objects.filter(user=request.user).values('item_id')))
        else:
             queryset = models.Item.objects.filter(Q(created_by=request.user) | Q(id__in=models.Share.objects.filter(user=request.user).values('item_id')))
        ser = serializer.GetItemsSerializer(queryset, many=True,context={'user': request.user.id})
        return Response(ser.data)

 
    def retrieve(self, request, pk=None):
        queryset = models.Item.objects.get(pk=pk)
        self.check_object_permissions(self.request, queryset)
        ser = serializer.GetItemsSerializer(queryset, many=False, context={'user': request.user.id})
        return Response(ser.data)


    def partial_update(self, request, pk=None):
        queryset = models.Item.objects.get(pk=pk)
        self.check_object_permissions(self.request, queryset)
        try:
            if "title" in request.data:
                queryset.title = request.data["title"]
            if "password" in request.data:
                key = Fernet.generate_key() 
                fernet = Fernet(key)
                encPass = fernet.encrypt(request.data["password"].encode()) 
                queryset.password = codecs.decode(encPass, 'UTF-8')
                queryset.key = codecs.decode(key, 'UTF-8')
            queryset.save()
            msg = True
            dat = queryset.id
            stat = status.HTTP_200_OK
            errors = []
        except:
            dat = []
            msg = False
            errors = {"error":"field not found/error"}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)



class Share(viewsets.ModelViewSet):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, SharePermssion)
    queryset = models.Share.objects.all()
    serializer_class = serializer.ShareSerializer

    def destroy(self, request, pk=None):
        msg = False
        try:
            queryset = models.Share.objects.get(pk=pk,shared_by=request.user)
            queryset.delete()
            msg = True
            stat  = status.HTTP_200_OK
            dat = []
            errors = []
        except:
            dat = []
            msg = False
            errors = {"failed":"no member/permission"}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)


    def create(self, request, *args, **kwargs):
        msg = False
        self.check_object_permissions(self.request, request.data["item"])
        ser = serializer.ShareSerializer(data=request.data)
        ser.is_valid()
        try:
            ser.validated_data["shared_by"] = request.user
            user = User.objects.get(email=request.data["user"])
            ser.validated_data["user"] = user
            try:
                ser.save()
                msg = True
                dat = ser.data["id"]
                stat = status.HTTP_200_OK
                errors = []
            except Exception as e:
                dat = []
                msg = False
                errors = ser.errors
                stat = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            dat = []
            msg = False
            errors = {"error":"field not found/error" + str(e)}
            stat = status.HTTP_400_BAD_REQUEST
        return Response({'success': msg, 'data': dat, 'errors': errors}, status=stat)


    





    



