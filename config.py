import os, ConfigParser
basedir = os.path.abspath(os.path.dirname(__file__))

cfg = ConfigParser.ConfigParser()

if os.environ.get('DATABASE_URL') is None:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
else:
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

WTF_CSRF_ENABLED = cfg.get('Config', 'WTF_CSRF_ENABLED')
SECRET_KEY = cfg.get('Config', 'SecretKey')

OPENID_PROVIDERS = [
    {'name': 'Google', 'url': 'https://www.google.com/accounts/o8/id'},
    {'name': 'Yahoo', 'url': 'https://me.yahoo.com'},
    {'name': 'AOL', 'url': 'http://openid.aol.com/<username>'},
    {'name': 'Flickr', 'url': 'http://www.flickr.com/<username>'},
    {'name': 'MyOpenID', 'url': 'https://www.myopenid.com'}]

SWEAR_LIST = [word for word in cfg.get('Config', 'SwearWords')]

# mail server settings
MAIL_SERVER = cfg.get('Mail', 'MAIL_SERVER')
MAIL_PORT = cfg.get('Mail', 'MAIL_PORT')
MAIL_USERNAME = cfg.get('Mail', 'MAIL_USERNAME')
MAIL_PASSWORD = cfg.get('Mail', 'MAIL_PASSWORD')

#administrator list
ADMINS = [email for email in cfg.get('Config', 'Admins')]

#whoosh stuff
WHOOSH_BASE = os.path.join(basedir, 'search.db')
MAX_SEARCH_RESULTS = cfg.get('Whoosh', 'MAX_RESULTS')