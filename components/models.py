from django.db import models


class AutoPartConditions(models.TextChoices):
    NEW = "NEW", "New"
    USED = "USED", "Used"
    REFURBISHED = "REFURBISHED", "Refurbished"


class Category(models.Model):
    name = models.CharField(max_length=255)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='subcategories')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Categories"


class Component(models.Model):
    provider = models.ForeignKey('accounts.Provider', on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    manufacturer = models.CharField(max_length=100, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    stock = models.IntegerField(null=True)
    image = models.ImageField(upload_to='component_images', null=True)
    weight = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    dimensions = models.CharField(max_length=100, blank=True)
    # the physical location of the component in the store or the warehouse
    location = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return self.name


class AutoPart(models.Model):
    component = models.OneToOneField(Component, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True, blank=True)
    vehicle_make = models.CharField(max_length=100, blank=True)
    vehicle_model = models.CharField(max_length=100, blank=True)
    vehicle_year = models.CharField(max_length=100, blank=True)
    condition = models.CharField(max_length=100, choices=AutoPartConditions.choices, blank=True)

    # Original Equipment Manufacturer number.This is a unique number that identifies the part.
    oem_number = models.CharField(max_length=100, blank=True)
    upc_number = models.CharField(max_length=100, blank=True)  # Universal Product Code number. if available

    class Meta:
        ordering = ['id']

    def __str__(self):
        parts = [self.category, self.vehicle_make, self.vehicle_model, self.vehicle_year, self.condition]
        return '->'.join(part for part in parts if part)
