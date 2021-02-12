# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
from flask import Flask 
from flask_cors import CORS
from dotenv import load_dotenv

# configuration
DEBUG = True

load_dotenv()

# Set up the app and point it to Vue
app = Flask(__name__, static_folder='../client/dist/',    static_url_path='/')
app.config.from_object(__name__)

# enable CORS
CORS(app)

### Blueprint
from server.area51 import area51 as area51_blueprint
app.register_blueprint(area51_blueprint, url_prefix='/area51')
