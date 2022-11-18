from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'dbsecret'
db = SQLAlchemy(app)
app.config["UPLOAD_FOLDER"]="./flaskacl/static/images/"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

from Interview import routes
