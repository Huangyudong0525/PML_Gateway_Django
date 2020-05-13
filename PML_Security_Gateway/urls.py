"""PML_Security_Gateway URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from SFC import views
urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^index/',views.index),
    url(r'^nf_router/',views.start_nf_router),
    url(r'^firewall/', views.start_firewall),
    url(r'^bridge/', views.start_bridge),
    url(r'^del_nf/', views.stop_nf),
    url(r'^read_nf_router_conf/', views.read_nf_router_conf),
    url(r'^nf_router_conf/', views.nf_router_conf),
    url(r'^del_nf_router_conf/', views.del_nf_router_conf),
    url(r'^read_firewall_conf/', views.read_firewall_conf),
    url(r'^firewall_conf/', views.firewall_conf),
    url(r'^del_firewall_conf/', views.del_firewall_conf),
    url(r'^flow_monitoring/', views.flow_monitoring),
    url(r'^system_monitoring/', views.system_monitoring),
    url(r'^read_nf/', views.read_nf),
    url(r'^aes_encrypt/', views.aes_encrypt),
    url(r'^aes_decrypt/', views.aes_decrypt),
]
