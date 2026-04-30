"""Sample Flask application for testing ApiPosture."""

from flask import Flask, jsonify, request

app = Flask(__name__)


# Simulated auth decorators
def login_required(f):
    """Decorator to require login."""
    def wrapper(*args, **kwargs):
        # Check for auth header
        auth = request.headers.get("Authorization")
        if not auth:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def roles_required(*roles):
    """Decorator to require specific roles."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            # Check for role
            user_role = request.headers.get("X-User-Role")
            if user_role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def admin_required(f):
    """Decorator to require admin role."""
    return roles_required("admin")(f)


# Public endpoints (should trigger AP001, AP008)
@app.route("/")
def index():
    """Public index endpoint."""
    return jsonify({"message": "Hello World"})


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"})


# Public write endpoint (should trigger AP004)
@app.route("/public/submit", methods=["POST"])
def public_submit():
    """Public submit endpoint - should have auth."""
    return jsonify({"received": request.json})


# Protected endpoints
@app.route("/profile")
@login_required
def get_profile():
    """Get user profile - protected."""
    return jsonify({"user": "testuser"})


@app.route("/users", methods=["POST"])
@login_required
def create_user():
    """Create user - protected."""
    return jsonify({"created": request.json})


@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    """Delete user - admin only."""
    return jsonify({"deleted": user_id})


# Endpoint with multiple roles (should trigger AP005 if >3)
@app.route("/reports")
@roles_required("admin", "manager", "analyst", "viewer")
def get_reports():
    """Get reports - many roles."""
    return jsonify({"reports": []})


# Endpoint with weak role name (should trigger AP006)
@app.route("/data")
@roles_required("user")
def get_data():
    """Get data - weak role name."""
    return jsonify({"data": []})


# Sensitive route that's public (should trigger AP007)
@app.route("/admin/config")
def admin_config():
    """Admin config - should not be public."""
    return jsonify({"config": {}})


# Blueprint example
from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@api_bp.route("/items")
@login_required
def list_items():
    """List items - protected."""
    return jsonify([])


@api_bp.route("/items", methods=["POST"])
@login_required
def create_item():
    """Create item - protected."""
    return jsonify(request.json)


app.register_blueprint(api_bp)


if __name__ == "__main__":
    app.run(debug=True)
