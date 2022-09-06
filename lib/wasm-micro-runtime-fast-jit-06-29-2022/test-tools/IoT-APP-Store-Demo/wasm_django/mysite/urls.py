#config:utf-8

"""mysite URL Configuration

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
#from django.conf.urls import include,url
from django.urls import path,include
from devices import views as devices_views
#from login import views as login_views


urlpatterns = [

    path('admin/', admin.site.urls),
    path('',devices_views.index),
    path('apps/',devices_views.apps),
    path('appDownload/', devices_views.appDownload),
    path('appDelete/', devices_views.appDelete),
    path('appstore/',devices_views.store),
##    path('apps/appstore/',devices_views.storeofdevic),
##    path('search/',devices_views.search),
    path('upload',devices_views.uploadapps),
    path('removeapps/',devices_views.removeapps),
    path('help/',devices_views.help),
    
]


