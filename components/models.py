from django.db import models


class AutoPartConditions(models.TextChoices):
    NEW = "NEW", "New"
    USED = "USED", "Used"
    REFURBISHED = "REFURBISHED", "Refurbished"


class AutoPartCategories(models.TextChoices):
    ACCESSORIES = "ACCESSORIES", "Accessories"
    AIR_CONDITIONING_AND_HEATING = "AIR_CONDITIONING_AND_HEATING", "Air Conditioning & Heating"
    ALTERNATORS_AND_STARTERS = "ALTERNATORS_AND_STARTERS", "Alternators & Starters"
    BATTERY_AND_ACCESSORIES = "BATTERY_AND_ACCESSORIES", "Battery & Accessories"
    BEARING_AND_SEALS = "BEARING_AND_SEALS", "Bearing & Seals"
    BELTS_AND_HOSES = "BELTS_AND_HOSES", "Belts & Hoses"
    BRAKES = "BRAKES", "Brakes",
    CV_DRIVESHAFT_AND_AXLE = "CV_DRIVESHAFT_AND_AXLE", "CV, Driveshaft & Axle"
    CHASSIS_AND_STEERING = "CHASSIS_AND_STEERING", "Chassis & Steering"
    DETAILING = "DETAILING", "Detailing"
    ENGINE_COOLING = "ENGINE_COOLING", "Engine Cooling"
    ENGINE_SENSORS_AND_EMISSIONS = "ENGINE_SENSORS_AND_EMISSIONS", "Engine Sensors & Emissions"
    ENGINES_AND_TRANSMISSIONS = "ENGINES_AND_TRANSMISSIONS", "Engines & Transmissions"
    EXHAUST = "EXHAUST", "Exhaust"
    FILTERS = "FILTERS", "Filters"
    FUEL_DELIVERY = "FUEL_DELIVERY", "Fuel Delivery"
    GASKETS = "GASKETS", "Gaskets"
    HARDWARE_AND_FASTENERS = "HARDWARE_AND_FASTENERS", "Hardware & Fasteners"
    HEAVY_DUTY_AG_AND_FLEET = "HEAVY_DUTY_AG_AND_FLEET", "Heavy Duty, Ag & Fleet"
    IGNITION_AND_TUNE_UP = "IGNITION_AND_TUNE_UP", "Ignition & Tune-Up"
    LAWN_AND_GARDEN = "LAWN_AND_GARDEN", "Lawn & Garden"
    LIGHTING_AND_ELECTRICAL = "LIGHTING_AND_ELECTRICAL", "Lighting & Electrical"
    MARINE_AND_BOAT = "MARINE_AND_BOAT", "Marine & Boat"
    MORE_POWERSPORT = "MORE_POWERSPORT", "More Powersport"
    OIL_CHEMICALS_AND_FLUIDS = "OIL_CHEMICALS_AND_FLUIDS", "Oil, Chemicals & Fluids"
    PAINT_AND_BODY = "PAINT_AND_BODY", "Paint & Body"
    PERFORMANCE = "PERFORMANCE", "Performance"
    RECREATIONAL_VEHICLE = "RECREATIONAL_VEHICLE", "Recreational Vehicle"
    SHOCKS_AND_STRUTS = "SHOCKS_AND_STRUTS", "Shocks & Struts"
    TIRE_AND_WHEEL = "TIRE_AND_WHEEL", "Tire & Wheel"
    TOOLS_AND_EQUIPMENT = "TOOLS_AND_EQUIPMENT", "Tools & Equipment"
    TRUCK_TOWING_AND_JEEP = "TRUCK_TOWING_AND_JEEP", "Truck, Towing & Jeep"
    TURBOCHARGER_AND_SUPERCHARGER = "TURBOCHARGER_AND_SUPERCHARGER", "Turbocharger & Supercharger"
    WIPERS_AND_COMPONENTS = "WIPERS_AND_COMPONENTS", "Wipers & Components"


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
    category = models.CharField(max_length=20, choices=AutoPartCategories.choices, blank=True)
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
