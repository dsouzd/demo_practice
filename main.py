from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import psycopg2
from psycopg2 import sql
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = os.getenv("DATABASE_URL")

class UserRegistration(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

@app.post("/register")
async def register_user(user: UserRegistration):
    hashed_password = hash_password(user.password)

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM user_data.user_details WHERE email = %s", [user.email])
        existing_user = cursor.fetchone()

        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        cursor.execute(
            sql.SQL("INSERT INTO user_data.user_details (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)"),
            [user.first_name, user.last_name, user.email, hashed_password]
        )
        conn.commit()

        return {"message": "User registered successfully"}
    
    except Exception as e:
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

    if result is None:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    stored_password_hash = result[1]
    if not pwd_context.verify(user.password, stored_password_hash):
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cursor.close()
    conn.close()
    return {"message": "Login successful"}
