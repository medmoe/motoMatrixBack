from django_elasticsearch_dsl import Document
from django_elasticsearch_dsl.registries import registry
from .models import AutoPart, Component, Category


@registry.register_document
class AutoPartDocument(Document):
    class Index:
        name = "auto_parts"
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }

    class Django:
        model = Component
        fields = [
            'name',
            'manufacturer',
            'description',
        ]

