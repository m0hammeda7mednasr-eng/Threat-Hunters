import os

class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    SECRET_KEY = os.getenv("SECRET_KEY")
    HIBP_API_KEY = os.getenv("HIBP_API_KEY")

    # JWT
    JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", 2))

    # Debug
    DEBUG = True