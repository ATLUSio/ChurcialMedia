import ConfigParser

cfg = ConfigParser.ConfigParser()

TIMEOUT = cfg.get('Gunicorn', 'TIMEOUT')
accesslog = cfg.get('Gunicorn', 'ACCESSLOG')
errorlog = cfg.get('Gunicorn', 'ERRORLOG')
