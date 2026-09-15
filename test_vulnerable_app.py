import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Vulnerable SQL Injection Route
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # VULNERABILITY: Raw string concatenation in SQL query
    query = "SELECT * FROM users WHERE id = '" + str(user_id) + "'"
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    return str(user)

# Vulnerable XSS Route
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # VULNERABILITY: Direct unescaped user input in response
    return f"<h1>Hello {name}</h1>"

if __name__ == '__main__':
    app.run(port=5000)