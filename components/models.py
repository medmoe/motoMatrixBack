from django.db import models
from accounts.models import Provider
from .types import CATEGORY, CONDITION


class Component(models.Model):
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    manufacturer = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.IntegerField()
    image = models.ImageField(upload_to='component_images', blank=True)
    weight = models.DecimalField(max_digits=10, decimal_places=2)
    dimensions = models.CharField(max_length=100)
    location = models.CharField(max_length=100)  # the physical location of the component in the store or the warehouse

    class Meta:
        abstract = True


class AutoPart(Component):
    category = models.CharField(max_length=20, choices=CATEGORY, blank=True)
    vehicle_make = models.CharField(max_length=100)
    vehicle_model = models.CharField(max_length=100)
    vehicle_year = models.CharField(max_length=100)
    condition = models.CharField(max_length=100, choices=CONDITION)
    # Original Equipment Manufacturer number.This is a unique number that identifies the part.
    OEM_number = models.CharField(max_length=100, blank=True)
    UPC_number = models.CharField(max_length=100, blank=True)  # Universal Product Code number. if available
