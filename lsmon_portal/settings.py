import base64
import os

SECRET_KEY = os.environ.get("LSMON_DJANGO_SECRET_KEY", "unsafe-local-test-key-not-for-deployment")
DEBUG = os.environ.get("LSMON_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [host.strip() for host in os.environ.get("LSMON_PUBLIC_HOST", "").split(",") if host.strip()]
ROOT_URLCONF = "lsmon_portal.urls"
INSTALLED_APPS = [
    "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.messages", "django.contrib.staticfiles", "lsmon_core",
]
DATABASES = {"default": {
    "ENGINE": os.environ.get("LSMON_DB_ENGINE", "django.db.backends.sqlite3"),
    "NAME": os.environ.get("LSMON_DB_NAME", "lsmon-test.sqlite3"),
    "USER": os.environ.get("LSMON_DB_USER", ""),
    "PASSWORD": os.environ.get("LSMON_DB_PASSWORD", ""),
    "HOST": os.environ.get("LSMON_DB_HOST", ""),
    "PORT": os.environ.get("LSMON_DB_PORT", ""),
}}
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
STATIC_URL = "/static/"
STATICFILES_DIRS = [os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")]
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

# These become active only when the reverse proxy/tunnel is explicitly configured
# for HTTPS. The application is intentionally not exposed before that point.
BEHIND_TLS = os.environ.get("LSMON_BEHIND_TLS", "false").lower() == "true"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if BEHIND_TLS else None
SECURE_SSL_REDIRECT = BEHIND_TLS
SESSION_COOKIE_SECURE = BEHIND_TLS
CSRF_COOKIE_SECURE = BEHIND_TLS
SECURE_HSTS_SECONDS = 31536000 if BEHIND_TLS else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = BEHIND_TLS
SECURE_HSTS_PRELOAD = False
X_FRAME_OPTIONS = "DENY"
LSMON_MFA_ENCRYPTION_KEY = os.environ.get("LSMON_MFA_ENCRYPTION_KEY")

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.environ.get("LSMON_SMTP_HOST", "")
EMAIL_PORT = int(os.environ.get("LSMON_SMTP_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("LSMON_SMTP_USERNAME", "")
_smtp_password = os.environ.get("LSMON_SMTP_PASSWORD_B64", "")
EMAIL_HOST_PASSWORD = base64.b64decode(_smtp_password).decode() if _smtp_password else ""
EMAIL_USE_TLS = os.environ.get("LSMON_SMTP_USE_TLS", "true").lower() == "true"
EMAIL_USE_SSL = os.environ.get("LSMON_SMTP_USE_SSL", "false").lower() == "true"
EMAIL_TIMEOUT = 20
DEFAULT_FROM_EMAIL = os.environ.get("LSMON_SMTP_FROM", "")
SERVER_EMAIL = DEFAULT_FROM_EMAIL
