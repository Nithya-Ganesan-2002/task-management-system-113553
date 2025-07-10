from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import os

# Import database logic from db.py
from . import db

# App-level metadata for OpenAPI
app = FastAPI(
    title="TaskTrackr Backend API",
    description="Backend API for TaskTrackr with user authentication and task management.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User registration and authentication"},
        {"name": "tasks", "description": "CRUD operations for tasks"}
    ],
)

# Enable CORS for all origins (you might want to limit this for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURATION, CONSTANTS ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")  # Should be set in production env!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# --- UTILITY FUNCTIONS ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- MODELS ---
class UserRegistration(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=6, description="User's password (min 6 chars)")

class UserRead(BaseModel):
    id: int
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str

class TaskBase(BaseModel):
    title: str = Field(..., description="Task title")
    description: Optional[str] = Field(None, description="Details of the task")
    due_date: Optional[datetime] = Field(None, description="Due date of the task (RFC3339 format)")
    completed: Optional[bool] = Field(default=False, description="Task completion status")

class TaskCreate(TaskBase):
    pass

class TaskUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    due_date: Optional[datetime]
    completed: Optional[bool]

class TaskRead(TaskBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime

# --- AUTH HELPERS ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    # Decodes JWT and returns user row if valid, else raises HTTPException
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user_id = int(user_id)
    except JWTError:
        raise credentials_exception
    user = db.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user

# --- API: AUTH ---

# PUBLIC_INTERFACE
@app.post("/register", response_model=UserRead, tags=["auth"], summary="Register a new user")
def register(user: UserRegistration):
    """
    Register a new user.

    - **email**: user email
    - **password**: password (min 6 chars)
    Returns the new user id and email.
    """
    res = db.create_user(user.email, user.password)
    if res is None:
        raise HTTPException(status_code=409, detail="Email already registered")
    return {"id": res["id"], "email": res["email"]}

# PUBLIC_INTERFACE
@app.post("/token", response_model=Token, tags=["auth"], summary="Login (token-based)")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate user and return access token.

    - **username**: user email (not display name)
    - **password**: password
    Returns a Bearer access token on success.
    """
    user_row = db.get_user_by_email(form_data.username)
    if not user_row or not db.verify_password(form_data.password, user_row["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user_row["id"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- API: TASKS ---

# PUBLIC_INTERFACE
@app.post("/tasks/", response_model=TaskRead, tags=["tasks"], summary="Create a task")
def create_task(task: TaskCreate, current_user=Depends(get_current_user)):
    """
    Create a new task for the authenticated user.
    """
    row = db.create_task_for_user(
        user_id=current_user["id"],
        title=task.title,
        description=task.description,
        due_date=task.due_date,
        completed=task.completed or False,
    )
    return _row_to_taskread(row)

# PUBLIC_INTERFACE
@app.get("/tasks/", response_model=List[TaskRead], tags=["tasks"], summary="List all tasks for user")
def list_tasks(current_user=Depends(get_current_user)):
    """
    List all tasks for the authenticated user.
    """
    rows = db.get_tasks_for_user(current_user["id"])
    return [_row_to_taskread(row) for row in rows]

# PUBLIC_INTERFACE
@app.get("/tasks/{task_id}", response_model=TaskRead, tags=["tasks"], summary="Get a specific task")
def get_task(task_id: int, current_user=Depends(get_current_user)):
    """
    Get a single task by ID (must belong to authenticated user).
    """
    row = db.get_task_by_id_for_user(task_id, current_user["id"])
    if row is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return _row_to_taskread(row)

# PUBLIC_INTERFACE
@app.put("/tasks/{task_id}", response_model=TaskRead, tags=["tasks"], summary="Update a task")
def update_task(task_id: int, update: TaskUpdate, current_user=Depends(get_current_user)):
    """
    Update a task (partial update, fields in body are optional).
    """
    row = db.update_task_for_user(
        task_id=task_id,
        user_id=current_user["id"],
        title=update.title if update.title is not None else None,
        description=update.description if update.description is not None else None,
        due_date=update.due_date if update.due_date is not None else None,
        completed=update.completed if update.completed is not None else None,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return _row_to_taskread(row)

# PUBLIC_INTERFACE
@app.delete("/tasks/{task_id}", status_code=204, tags=["tasks"], summary="Delete a task")
def delete_task(task_id: int, current_user=Depends(get_current_user)):
    """
    Delete a task by its ID (must belong to authenticated user).
    """
    ok = db.delete_task_for_user(task_id, current_user["id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Task not found")
    return

# -- UTILITY: Mapping DB result to Pydantic --
def _row_to_taskread(row):
    # Converts row (sqlite3.Row) into TaskRead model, handling types (esp. for bool fields and datetimes)
    if row is None:
        return None
    return TaskRead(
        id=row["id"],
        title=row["title"],
        description=row["description"],
        due_date=datetime.fromisoformat(row["due_date"]) if row["due_date"] else None,
        completed=bool(row["completed"]),
        user_id=row["user_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )

# ----- Health Check -----
# PUBLIC_INTERFACE
@app.get("/", tags=["auth"], summary="Health Check")
def health_check():
    """
    Health check endpoint for TaskTrackr backend API.
    Returns message if API is alive.
    """
    return {"message": "Healthy"}

# --- OpenAPI Docs Note on WebSocket Usage (not implemented, just for completeness) ---
@app.get("/ws-docs", tags=["auth"], summary="WebSocket usage help", include_in_schema=True)
def websocket_usage():
    """This project uses only HTTP REST endpoints. No WebSocket endpoints are available."""
    return {"message": "No WebSocket endpoints. Use HTTP REST API for all TaskTrackr functionality."}
