from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from .models import ReportTemplate, GeneratedReport
from irp.accounts.models import Organization
from irp.cases.models import Case


# Write tests here 