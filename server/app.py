from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from routes.auth import auth_bp, bcrypt, jwt, create_resources
from models import db

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "We are winners"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
jwt.init_app(app)
mail = Mail(app)
migrate = Migrate(app, db)

# Register blueprints
app.register_blueprint(auth_bp)

# Create resources with the mail instance
create_resources(mail)

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)
