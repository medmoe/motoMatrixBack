from django_elasticsearch_dsl import Document
from django_elasticsearch_dsl.registries import registry

from .models import AutoPart


@registry.register_document
class AutoPartDocument(Document):
    class Index:
        name = 'autoparts'
        settings = {'number_of_shards': 1, 'number_of_replicas': 0}

    class Django:
        model = AutoPart
        fields = ['name']
