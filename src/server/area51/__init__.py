# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
from flask import Blueprint

area51 = Blueprint('area51', __name__)

from . import views
from ..common import Permission

@area51.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)
