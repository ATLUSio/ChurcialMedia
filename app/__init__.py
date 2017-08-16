
import os
from flask import Flask
from flask.ext.login import LoginManager
from flask.ext.sqlalchemy import SQLAlchemy
from config import basedir, ADMINS, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, SWEAR_LIST

app = Flask(__name__, static_url_path="")
app.config.from_object('config')
app.config['PERMANENT_SESSION_LIFETIME'] = 604800 #7 Days in secs
db = SQLAlchemy(app)

lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'

from app import views, models
