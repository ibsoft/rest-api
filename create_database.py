# import the required libraries
import sqlite3
from passlib.hash import pbkdf2_sha256

def create_users_table():
    # create the database connection
    conn = sqlite3.connect('users.db')

    # create cursor object
    cursor = conn.cursor()

    # create the users table
    cursor.execute('''CREATE TABLE users(
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL)''')

    # create two sample users
    password1 = pbkdf2_sha256.hash('password123', rounds=20000, salt_size=16)
    password2 = pbkdf2_sha256.hash('password456', rounds=20000, salt_size=16)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('john', password1))
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('susan', password2))

    # commit the changes and close the connection
    conn.commit()
    conn.close()

create_users_table()
