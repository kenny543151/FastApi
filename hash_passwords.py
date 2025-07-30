import mysql.connector
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_staff_passwords():
    try:
        connection = mysql.connector.connect(
            host="localhost",       # e.g., localhost
            port="3306",       # e.g., 3306
            database="sakila",
            user="root",   # e.g., root
            password="Nwulunwu@4135"
        )
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT staff_id, password FROM staff")
        for row in cursor.fetchall():
            hashed = pwd_context.hash(row["password"])
            cursor.execute(
                "UPDATE staff SET password = %s WHERE staff_id = %s",
                (hashed, row["staff_id"])
            )
        connection.commit()
        print("Staff passwords hashed successfully.")
        cursor.close()
        connection.close()
    except Exception as e:
        print(f"Error: {e}")
        if connection.is_connected():
            connection.rollback()

if __name__ == "__main__":
    hash_staff_passwords()