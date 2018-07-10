from django.conf.urls import url
from django.contrib import admin
from demo.views import index, attrs, metadata

admin.autodiscover()

urlpatterns = [
    url(r'^$', index, name='index'),
    url(r'^attrs/$', attrs, name='attrs'),
    url(r'^metadata/$', metadata, name='metadata')
]

