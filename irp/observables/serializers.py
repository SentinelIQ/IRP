from rest_framework import serializers
from django.contrib.auth.models import User

from .models import ObservableType, TLPLevel, PAPLevel, Observable
from irp.accounts.serializers import UserSerializer


class ObservableTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ObservableType
        fields = '__all__'


class TLPLevelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TLPLevel
        fields = '__all__'


class PAPLevelSerializer(serializers.ModelSerializer):
    class Meta:
        model = PAPLevel
        fields = '__all__'


class ObservableSerializer(serializers.ModelSerializer):
    type = ObservableTypeSerializer(read_only=True)
    tlp_level = TLPLevelSerializer(read_only=True)
    pap_level = PAPLevelSerializer(read_only=True)
    added_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Observable
        fields = '__all__'
        read_only_fields = ['observable_id', 'added_at']
