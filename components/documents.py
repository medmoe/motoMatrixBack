from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry
from .models import AutoPart, Component, Category


@registry.register_document
class AutoPartDocument(Document):
    component = fields.ObjectField(properties={
        'name': fields.TextField(),
        "manufacturer": fields.TextField(),
        "description": fields.TextField(),
    })

    category = fields.ObjectField(properties={
        'name': fields.TextField(),
    })

    class Index:
        name = "auto_parts"
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }

    class Django:
        model = AutoPart
        fields = []
        related_models = [Component, Category]

    def get_queryset(self):
        return super(AutoPartDocument, self).get_queryset().select_related('component', 'category')

    def get_instances_from_related(self, related_instance):
        if isinstance(related_instance, Component):
            return related_instance.autopart
        elif isinstance(related_instance, Category):
            return related_instance.autopart_set.all()
