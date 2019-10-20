import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_moment import Moment
from flask_oauth import OAuth
basedir = os.path.abspath(os.path.dirname(__file__))

# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = '286006964722-dm9g1vobdsap0mmgenlvi3b7i3lg99bh.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'fOMnHepXDI4sAPSZrX3ZfDfC'
REDIRECT_URI = '/authorized'  # one of the Redirect URIs from Google APIs console

app = Flask(__name__)
db = SQLAlchemy(app)
oauth = OAuth()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = "login"
login_manager.init_app(app)

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

#for displaying timestamps
moment = Moment(app)
import models
import views

app.config['SECRET_KEY'] = '\xeeJ\x01\xb7\xfa\xa4\xc8\xd32\x929\xd6XX#\xbd\x03\xcb\xeaf\x9d\x03\xcdN'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir, 'pureclock.db')
app.config['DEBUG'] = True

