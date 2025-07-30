from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Dict, Any, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
import mysql.connector
from mysql.connector import Error
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

# load environment variables
load_dotenv()

# jwt configuration
SECRET_KEY = os.getenv("SECRET_KEY", "8f3a47b6e9d2c5f1a0e7d4b2c8f6a3e9d5b1c7f2a8e4d6b0c3f5a9e2d7b4c8")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# FastAPI app initialization
app = FastAPI(
    title="Sakila DVD Rental API",
    description="REST API for the Sakila DVD rental database with 12 secure endpoints",
    version="1.0.0"
)

# OAuth2 scheme for token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database connection function
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT", "3306"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD")
        )
        if connection.is_connected():
            return connection
    except Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database connection error: {str(e)}"
        )

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM staff WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    return user

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    connection = get_db_connection()
    user = get_user(connection, username)
    connection.close()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Dict = Depends(get_current_user)):
    if not current_user.get("active", True):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

# Root endpoint (public)
@app.get("/")
async def read_root():
    return {"message": "Welcome to the Sakila DVD Rental API"}

# Authentication endpoints
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Generate JWT token"""
    connection = get_db_connection()
    user = authenticate_user(connection, form_data.username, form_data.password)
    connection.close()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.put("/token")
async def renew_access_token(current_user: Dict = Depends(get_current_active_user)):
    """Renew JWT token"""
    access_token = create_access_token(data={"sub": current_user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
async def invalidate_token(current_user: Dict = Depends(get_current_active_user)):
    """Invalidate JWT token (simulated)"""
    return {}

# GET endpoints (using views)
@app.get("/films", response_model=List[Dict])
async def get_films(current_user: Dict = Depends(get_current_active_user)):
    """Get list of films (no parameters) - uses film_list view"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        query = """
        SELECT FID as film_id, title, description, category, price as rental_rate,
               length, rating, actors
        FROM film_list
        LIMIT 100
        """
        cursor.execute(query)
        films = cursor.fetchall()
        return films
    except Error as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {str(e)}")
    finally:
        cursor.close()
        connection.close()

@app.get("/customers/{store_id}", response_model=List[Dict])
async def get_customers_by_store(
    store_id: int, current_user: Dict = Depends(get_current_active_user)
):
    """Get customers by store ID (with parameter) - uses customer_list view"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT store_id FROM store WHERE store_id = %s", (store_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Store not found")
        query = """
        SELECT ID as customer_id, name, address, `zip code` as zip_code,
               phone, city, country, notes, SID as active
        FROM customer_list
        WHERE SID = %s
        """
        cursor.execute(query, (store_id,))
        customers = cursor.fetchall()
        if not customers:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No customers found")
        return customers
    except Error as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {str(e)}")
    finally:
        cursor.close()
        connection.close()

@app.get("/sales/{store_id}", response_model=Dict)
async def get_store_sales(
    store_id: int, current_user: Dict = Depends(get_current_active_user)
):
    """Get store sales (with parameter) - uses sales_by_store view"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT store_id FROM store WHERE store_id = %s", (store_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Store not found")
        store_mapping = {1: "Woodridge,Australia", 2: "Lethbridge,Canada"}
        if store_id not in store_mapping:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid store ID")
        query = "SELECT store, manager, total_sales FROM sales_by_store WHERE store = %s"
        cursor.execute(query, (store_mapping[store_id],))
        sales = cursor.fetchone()
        if not sales:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No sales data found")
        return sales
    except Error as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {str(e)}")
    finally:
        cursor.close()
        connection.close()

# POST endpoints
@app.post("/customers", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def create_customer(
    customer_data: Dict[str, Any], current_user: Dict = Depends(get_current_active_user)
):
    """Create a new customer"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        required_fields = ["store_id", "first_name", "last_name", "email", "address_id"]
        for field in required_fields:
            if field not in customer_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Missing field: {field}")
        cursor.execute("SELECT email FROM customer WHERE email = %s", (customer_data["email"],))
        if cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
        cursor.execute("SELECT address_id FROM address WHERE address_id = %s", (customer_data["address_id"],))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid address ID")
        cursor.execute("SELECT store_id FROM store WHERE store_id = %s", (customer_data["store_id"],))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid store ID")
        create_date = datetime.now()
        query = """
        INSERT INTO customer
        (store_id, first_name, last_name, email, address_id, active, create_date, last_update)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            customer_data["store_id"],
            customer_data["first_name"],
            customer_data["last_name"],
            customer_data["email"],
            customer_data["address_id"],
            customer_data.get("active", 1),
            create_date,
            create_date
        )
        cursor.execute(query, values)
        customer_id = cursor.lastrowid
        connection.commit()
        cursor.execute("SELECT * FROM customer WHERE customer_id = %s", (customer_id,))
        new_customer = cursor.fetchone()
        for key, value in new_customer.items():
            if isinstance(value, datetime):
                new_customer[key] = value.isoformat()
        return new_customer
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to create customer: {str(e)}")
    finally:
        cursor.close()
        connection.close()

@app.post("/rentals", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def create_rental(
    rental_data: Dict[str, Any], current_user: Dict = Depends(get_current_active_user)
):
    """Create a new rental"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        required_fields = ["inventory_id", "customer_id", "staff_id"]
        for field in required_fields:
            if field not in rental_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Missing field: {field}")
        cursor.execute("SELECT customer_id FROM customer WHERE customer_id = %s AND active = 1", (rental_data["customer_id"],))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active customer not found")
        cursor.execute("SELECT staff_id FROM staff WHERE staff_id = %s", (rental_data["staff_id"],))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Staff not found")
        cursor.execute("""
            SELECT inventory_id FROM inventory
            WHERE inventory_id = %s AND inventory_id NOT IN (
                SELECT inventory_id FROM rental
                WHERE return_date IS NULL AND inventory_id = %s
            )
        """, (rental_data["inventory_id"], rental_data["inventory_id"]))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inventory item not available")
        rental_date = datetime.now()
        query = """
        INSERT INTO rental
        (rental_date, inventory_id, customer_id, staff_id, last_update)
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (
            rental_date,
            rental_data["inventory_id"],
            rental_data["customer_id"],
            rental_data["staff_id"],
            rental_date
        )
        cursor.execute(query, values)
        rental_id = cursor.lastrowid
        connection.commit()
        cursor.execute("SELECT * FROM rental WHERE rental_id = %s", (rental_id,))
        new_rental = cursor.fetchone()
        for key, value in new_rental.items():
            if isinstance(value, datetime):
                new_rental[key] = value.isoformat()
        return new_rental
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to create rental: {str(e)}")
    finally:
        cursor.close()
        connection.close()

# PUT endpoints
@app.put("/customers/{customer_id}", response_model=Dict)
async def update_customer(
    customer_id: int, customer_data: Dict[str, Any], current_user: Dict = Depends(get_current_active_user)
):
    """Update customer information"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT customer_id FROM customer WHERE customer_id = %s", (customer_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
        update_parts = []
        values = []
        allowed_fields = ["first_name", "last_name", "email", "active", "address_id"]
        for field in allowed_fields:
            if field in customer_data:
                update_parts.append(f"{field} = %s")
                values.append(customer_data[field])
        if not update_parts:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")
        if "email" in customer_data:
            cursor.execute("SELECT customer_id FROM customer WHERE email = %s AND customer_id != %s", 
                           (customer_data["email"], customer_id))
            if cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
        if "address_id" in customer_data:
            cursor.execute("SELECT address_id FROM address WHERE address_id = %s", (customer_data["address_id"],))
            if not cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid address ID")
        update_parts.append("last_update = %s")
        values.append(datetime.now())
        query = f"UPDATE customer SET {', '.join(update_parts)} WHERE customer_id = %s"
        values.append(customer_id)
        cursor.execute(query, values)
        connection.commit()
        cursor.execute("SELECT * FROM customer WHERE customer_id = %s", (customer_id,))
        updated_customer = cursor.fetchone()
        for key, value in updated_customer.items():
            if isinstance(value, datetime):
                updated_customer[key] = value.isoformat()
        return updated_customer
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to update customer: {str(e)}")
    finally:
        cursor.close()
        connection.close()

@app.put("/films/{film_id}", response_model=Dict)
async def update_film(
    film_id: int, film_data: Dict[str, Any], current_user: Dict = Depends(get_current_active_user)
):
    """Update film information"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT film_id FROM film WHERE film_id = %s", (film_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Film not found")
        update_parts = []
        values = []
        allowed_fields = ["title", "rental_rate", "length", "rating"]
        for field in allowed_fields:
            if field in film_data:
                update_parts.append(f"{field} = %s")
                values.append(film_data[field])
        if not update_parts:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")
        update_parts.append("last_update = %s")
        values.append(datetime.now())
        query = f"UPDATE film SET {', '.join(update_parts)} WHERE film_id = %s"
        values.append(film_id)
        cursor.execute(query, values)
        connection.commit()
        cursor.execute("SELECT * FROM film WHERE film_id = %s", (film_id,))
        updated_film = cursor.fetchone()
        for key, value in updated_film.items():
            if isinstance(value, datetime):
                updated_film[key] = value.isoformat()
        return updated_film
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to update film: {str(e)}")
    finally:
        cursor.close()
        connection.close()

# DELETE endpoints
@app.delete("/customers/{customer_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_customer(
    customer_id: int, current_user: Dict = Depends(get_current_active_user)
):
    """Deactivate a customer"""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT customer_id FROM customer WHERE customer_id = %s AND active = 1", (customer_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active customer not found")
        cursor.execute("SELECT rental_id FROM rental WHERE customer_id = %s AND return_date IS NULL", (customer_id,))
        if cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate customer with active rentals")
        cursor.execute("UPDATE customer SET active = 0, last_update = %s WHERE customer_id = %s", 
                       (datetime.now(), customer_id))
        connection.commit()
        return {}
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to deactivate customer: {str(e)}")
    finally:
        cursor.close()
        connection.close()

@app.delete("/rentals/{rental_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rental(
    rental_id: int, current_user: Dict = Depends(get_current_active_user)
):
    """Delete a rental"""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT rental_id, return_date FROM rental WHERE rental_id = %s", (rental_id,))
        rental = cursor.fetchone()
        if not rental:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rental not found")
        if rental[1]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete returned rental")
        cursor.execute("SELECT payment_id FROM payment WHERE rental_id = %s", (rental_id,))
        if cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete rental with payments")
        cursor.execute("DELETE FROM rental WHERE rental_id = %s", (rental_id,))
        connection.commit()
        return {}
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to delete rental: {str(e)}")
    finally:
        cursor.close()
        connection.close()
