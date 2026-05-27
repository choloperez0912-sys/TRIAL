import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "replace_with_secure_secret")
    DATABASE_URL = os.environ.get("DATABASE_URL")
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    CAMERA_MODE = os.environ.get("CAMERA_MODE", "local").lower()
    LOCAL_CAMERA_INDEX = os.environ.get("LOCAL_CAMERA_INDEX", "0")
    PUBLIC_CAMERA_URL = os.environ.get("PUBLIC_CAMERA_URL", "")
    IP_RATE_LIMIT = os.environ.get("IP_RATE_LIMIT", "15 per minute")
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
    DEFAULT_ALLOWED_IP = os.environ.get("DEFAULT_ALLOWED_IP")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASK_ENV = os.environ.get("FLASK_ENV", "production")

    @staticmethod
    def get_camera_mode():
        mode = os.environ.get("CAMERA_MODE", "local").lower()
        return mode if mode in ("local", "public") else "local"

    @staticmethod
    def get_local_camera_index():
        try:
            return int(os.environ.get("LOCAL_CAMERA_INDEX", "0"))
        except ValueError:
            return 0
