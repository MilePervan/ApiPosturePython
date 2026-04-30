"""Sample FastAPI application for testing ApiPosture."""

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, OAuth2PasswordBearer

app = FastAPI(title="Sample FastAPI App")

# Security schemes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
bearer_scheme = HTTPBearer()


# Simulated auth dependency
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from token."""
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"username": "testuser"}


async def get_admin_user(user: dict = Depends(get_current_user)):
    """Require admin user."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user


# Public endpoints (should trigger AP001, AP008)
@app.get("/")
async def root():
    """Public root endpoint."""
    return {"message": "Hello World"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Public write endpoint (should trigger AP004)
@app.post("/public/submit")
async def public_submit(data: dict):
    """Public submit endpoint - should have auth."""
    return {"received": data}


# Protected endpoints
@app.get("/users/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Get current user - protected."""
    return user


@app.post("/users")
async def create_user(user_data: dict, current_user: dict = Depends(get_current_user)):
    """Create user - protected."""
    return {"created": user_data}


@app.delete("/users/{user_id}")
async def delete_user(user_id: int, admin: dict = Depends(get_admin_user)):
    """Delete user - admin only."""
    return {"deleted": user_id}


# Endpoint with scopes
@app.get("/admin/stats")
async def admin_stats(token: str = Security(oauth2_scheme, scopes=["admin:read"])):
    """Admin stats with scope."""
    return {"stats": {}}


# Sensitive route that's public (should trigger AP007)
@app.get("/debug/info")
async def debug_info():
    """Debug endpoint - should not be public."""
    return {"debug": True}


# Router-based endpoints
from fastapi import APIRouter

api_router = APIRouter(prefix="/api/v1", dependencies=[Depends(get_current_user)])


@api_router.get("/items")
async def list_items():
    """List items - inherits auth from router."""
    return []


@api_router.post("/items")
async def create_item(item: dict):
    """Create item - inherits auth from router."""
    return item


app.include_router(api_router)
