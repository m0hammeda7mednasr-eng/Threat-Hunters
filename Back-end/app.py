from dotenv import load_dotenv
import os
load_dotenv()
from flask import Flask
from flask_cors import CORS
from config import Config
from database.db import mongo
from routes.user_routes import user_bp
from routes.auth_routes import auth_bp
from routes.blog_routes import blog_bp

app = Flask(__name__)
app.config.from_object(Config)

CORS(app)
mongo.init_app(app)

app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(user_bp, url_prefix="/api")
app.register_blueprint(blog_bp, url_prefix="/api")
#print("SECRET:", os.getenv("SECRET_KEY"))


if __name__ == "__main__":
    app.run(debug=True)