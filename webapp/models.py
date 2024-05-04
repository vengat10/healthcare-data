from django.db import models

class Document(models.Model):
    label = models.CharField(max_length=100)
    textarea = models.TextField()

    def __str__(self):
        return self.label
