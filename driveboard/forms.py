from django import forms
from .models import Ideahistoria

class IdeaForm(forms.ModelForm):
    class Meta:
        model = Ideahistoria
        fields = ["title_idea", "descripcion"]