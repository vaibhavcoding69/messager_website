import os
from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    
    # Drop existing tables if they exist
    c.execute("DROP TABLE IF EXISTS messages")
    c.execute("DROP TABLE IF EXISTS users")
    
    # Create tables with the correct schema
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    
    c.execute('''CREATE TABLE messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  content TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  user_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

# Call init_db() to ensure the tables are created with the correct schema
init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            session['user_id'] = c.lastrowid
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return "Username already exists. Choose a different one."
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            return "Invalid username or password"
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        message = request.form['message']
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute("INSERT INTO messages (content, user_id) VALUES (?, ?)", (message, session['user_id']))
        conn.commit()
        conn.close()
    
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT messages.id, messages.content, messages.timestamp, messages.user_id, users.username FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC")
    messages = c.fetchall()
    conn.close()
    
    return render_template('index.html', messages=messages)

@app.route('/api/messages', methods=['GET'])
def get_messages():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT messages.id, messages.content, messages.timestamp, messages.user_id, users.username FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC")
    messages = c.fetchall()
    conn.close()
    return jsonify([{'id': m[0], 'content': m[1], 'timestamp': m[2], 'user_id': m[3], 'username': m[4]} for m in messages])

if __name__ == '__main__':
    app.run(debug=True)