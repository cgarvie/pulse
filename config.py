import os

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode.
DEBUG = True

# Secret key for session management. You can generate random strings here:
# http://clsc.net/tools-old/random-string-generator.php
SECRET_KEY = 'my precious fksdfnlkds'

# Connect to the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'database.db')

SECURITY_PASSWORD_SALT = 'i_like_calklndy'


# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = 'cameronfldsnfkldsafnkl@gmail.com' #os.environ['APP_MAIL_USERNAME']
MAIL_PASSWORD = 'fdfnalsdfndlksfnkldsf'

# mail accounts
MAIL_DEFAULT_SENDER = 'cameronfdsafnalksdkl@gmail.com'
