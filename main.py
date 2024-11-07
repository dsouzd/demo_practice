from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, validator
from passlib.context import CryptContext
import psycopg2
from psycopg2 import sql
import os
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"], 
)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
DATABASE_URL = os.getenv("DATABASE_URL")

class UserRegistration(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)

    @validator("password")
    def password_strength(cls, value):
        if not any(char.isdigit() for char in value) or not any(char.isalpha() for char in value):
            raise ValueError("Password must contain at least one letter and one number")
        return value

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def get_db_connection():
    try:
        print(f"Connecting to database with URL: {DATABASE_URL}")  # Debug print
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Error connecting to database: {str(e)}")  # Debug print
        raise HTTPException(status_code=500, detail="Error connecting to database")

@app.post("/register")
async def register_user(user: UserRegistration):
    hashed_password = hash_password(user.password)
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Debug print to check if the database connection is established
        print("Database connection established.")
        
        cursor.execute("SELECT 1 FROM user_data.user_details WHERE email = %s", [user.email])
        existing_user = cursor.fetchone()
        
        if existing_user:
            print(f"User with email {user.email} already exists.")  # Debug print
            raise HTTPException(status_code=400, detail="Email already registered")

        cursor.execute(
            sql.SQL("INSERT INTO user_data.user_details (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)"),
            [user.first_name, user.last_name, user.email, hashed_password]
        )
        conn.commit()
        
        print("User registered successfully.")  # Debug print
        return {"message": "User registered successfully"}
    except Exception as e:
        print(f"Error during registration: {str(e)}")  # Debug print
        if conn is not None:
            conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error registering user: {str(e)}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

class UserLogin(BaseModel):
    email: EmailStr
    password: str

@app.post("/login")
async def validate_user(user: UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, password FROM user_data.user_details WHERE email = %s", [user.email])
    result = cursor.fetchone()
    
    # Debug print to check if the user exists in the database
    print(f"Login attempt for user: {user.email}")
    
    if result is None:
        cursor.close()
        conn.close()
        print(f"User {user.email} not found.")  # Debug print
        raise HTTPException(status_code=404, detail="User not found")

    stored_password_hash = result[1]
    if not pwd_context.verify(user.password, stored_password_hash):
        cursor.close()
        conn.close()
        print(f"Invalid credentials for user: {user.email}")  # Debug print
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cursor.close()
    conn.close()
    print(f"User {user.email} logged in successfully.")  # Debug print
    return {"message": "Login successful"}

class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=2, max_length=50)
    last_name: Optional[str] = Field(None, min_length=2, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)

    @validator("password")
    def password_strength(cls, value):
        if value and (not any(char.isdigit() for char in value) or not any(char.isalpha() for char in value)):
            raise ValueError("Password must contain at least one letter and one number")
        return value 
    
@app.get("/userdata/{email}")
async def get_user_data(email: EmailStr):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT first_name, last_name, email FROM user_data.user_details WHERE email = %s", [email])
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "first_name": user_data[0],
        "last_name": user_data[1],
        "email": user_data[2]
    }

@app.put("/edit/{email}")
async def edit_user_data(email: EmailStr, user_update: UserUpdate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT 1 FROM user_data.user_details WHERE email = %s", [email])
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="User not found")
        updates = []
        values = []
        if user_update.first_name:
            updates.append("first_name = %s")
            values.append(user_update.first_name)
        if user_update.last_name:
            updates.append("last_name = %s")
            values.append(user_update.last_name)
        if user_update.email:
            updates.append("email = %s")
            values.append(user_update.email)
        if user_update.password:
            hashed_password = hash_password(user_update.password)
            updates.append("password = %s")
            values.append(hashed_password)
        values.append(email)
        if updates:
            query = sql.SQL("UPDATE user_data.user_details SET {} WHERE email = %s").format(
                sql.SQL(", ").join(sql.SQL(u) for u in updates)
            )
            cursor.execute(query, values)
            conn.commit()
            return {"message": "User data updated successfully"}
        else:
            raise HTTPException(status_code=400, detail="No fields to update")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Error updating user data: {str(e)}")
    finally:
        cursor.close()
        conn.close()
