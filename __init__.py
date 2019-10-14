import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_moment import Moment
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view="login"
login_manager.init_app(app)

#for displaying timestamps
moment = Moment(app)
import models
import views

app.config['SECRET_KEY'] = '\xeeJ\x01\xb7\xfa\xa4\xc8\xd32\x929\xd6XX#\xbd\x03\xcb\xeaf\x9d\x03\xcdN'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir, 'thermos.db')
app.config['DEBUG'] = True

