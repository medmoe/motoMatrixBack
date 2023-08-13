from enum import Enum, unique

from django.db import models

from accounts.models import Provider


@unique
class AutoPartConditions(Enum):
    NEW = "NEW"
    USED = "USED"
    REFURBISHED = "REFURBISHED"


@unique
class AutoPartCategories(Enum):
    ENGINE = "ENGINE"
    TRANSMISSION = "TRANSMISSION"
    SUSPENSION = "SUSPENSION"
    BRAKES = "BRAKES"
    ELECTRICAL = "ELECTRICAL"
    BODY = "BODY"
    INTERIOR = "INTERIOR"
    TIRES = "TIRES"
    WHEELS = "WHEELS"
    ACCESSORIES = "ACCESSORIES"


class Component(models.Model):
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    manufacturer = models.CharField(max_length=100, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    stock = models.IntegerField(null=True)
    image = models.ImageField(upload_to='component_images', null=True)
    weight = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    dimensions = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=100,
                                blank=True)  # the physical location of the component in the store or the warehouse

    class Meta:
        abstract = True


class AutoPart(Component):
    auto_part_condition = [(condition.value, condition.name) for condition in AutoPartConditions]
    auto_part_category = [(category.value, category.name) for category in AutoPartCategories]
    category = models.CharField(max_length=20, choices=auto_part_category, blank=True)
    vehicle_make = models.CharField(max_length=100, blank=True)
    vehicle_model = models.CharField(max_length=100, blank=True)
    vehicle_year = models.CharField(max_length=100, blank=True)
    condition = models.CharField(max_length=100, choices=auto_part_condition, blank=True)

    # Original Equipment Manufacturer number.This is a unique number that identifies the part.
    OEM_number = models.CharField(max_length=100, blank=True)
    UPC_number = models.CharField(max_length=100, blank=True)  # Universal Product Code number. if available
