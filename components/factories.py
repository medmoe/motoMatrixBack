import factory
from factory.django import DjangoModelFactory

from .models import Component, AutoPart, AutoPartConditions, Category


class CategoryFactory(DjangoModelFactory):
    class Meta:
        model = Category

    name = factory.Iterator(Category.objects.values_list('name', flat=True))
    parent = factory.Maybe(
        factory.lazy_attribute(lambda o: o.parent),
        yes_declaration=factory.SubFactory('self'),
        no_declaration=None
    )


# Assuming you already have a ProviderFactory somewhere to generate providers.
# If not, you would need to create one similar to the below ComponentFactory and AutoPartFactory.
class ComponentFactory(DjangoModelFactory):
    class Meta:
        model = Component

    provider = factory.SubFactory('accounts.factories.ProviderFactory')  # Adjust path accordingly.
    name = factory.Faker('word')  # Generates a random word.
    description = factory.Faker('paragraph')
    manufacturer = factory.Faker('company')
    price = factory.Faker('pydecimal', left_digits=7, right_digits=2, positive=True)
    stock = factory.Faker('random_int', min=0, max=1000)
    # For the image, if you're using Django's default storage, you can use factory's ImageField.
    # However, remember to clean up images created during testing.
    image = factory.django.ImageField(filename=factory.Faker('file_name', extension='jpg'))
    weight = factory.Faker('pydecimal', left_digits=3, right_digits=2, positive=True)
    dimensions = factory.Faker('random_element', elements=["10x10x10", "5x5x5", "20x20x20"])
    location = factory.Faker('address')
    created_at = factory.Faker('date_time_this_decade', tzinfo=None)


class AutoPartFactory(DjangoModelFactory):
    class Meta:
        model = AutoPart

    component = factory.SubFactory(ComponentFactory)
    category = factory.Iterator(Category.objects.all())
    vehicle_make = factory.Faker('company')
    vehicle_model = factory.Faker('word')
    vehicle_year = factory.Faker('year')
    condition = factory.Faker('random_element', elements=[choice[0] for choice in AutoPartConditions.choices])
    oem_number = factory.Faker('isbn13')
    upc_number = factory.Faker('ean13')
