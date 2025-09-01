from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
CORS(app)

# Config
app.config["SECRET_KEY"] = "supersecretkey"  # Change in production
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# --------- DATABASE INIT ---------
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    # Users table
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    password TEXT)""")
    # Tasks table
    c.execute("""CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT,
                    description TEXT,
                    category TEXT,
                    priority TEXT,
                    status INTEGER DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id))""")
    conn.commit()
    conn.close()

init_db()

# --------- BASE ROUTES ---------
@app.route("/")
def home():
    return {"message": "Welcome to Check TodoList App Backend API"}


# --------- AUTH ROUTES ---------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username, email, password = data["username"], data["email"], data["password"]

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                  (username, email, pw_hash))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or Email already exists"}), 400


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user[1], password):
        token = create_access_token(identity=user[0])  # identity = user_id
        return jsonify({"token": token}), 200
    return jsonify({"error": "Invalid username or password"}), 401


# --------- TASK ROUTES ---------
@app.route("/tasks", methods=["GET"])
@jwt_required()
def get_tasks():
    user_id = get_jwt_identity()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE user_id=?", (user_id,))
    tasks = c.fetchall()
    conn.close()
    return jsonify(tasks)


@app.route("/tasks", methods=["POST"])
@jwt_required()
def add_task():
    user_id = get_jwt_identity()
    data = request.json
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("INSERT INTO tasks (user_id, title, description, category, priority, status) VALUES (?, ?, ?, ?, ?, ?)",
              (user_id, data["title"], data["description"], data["category"], data["priority"], int(data.get("status", 0))))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task added"}), 201


@app.route("/tasks/<int:task_id>", methods=["PUT"])
@jwt_required()
def update_task(task_id):
    user_id = get_jwt_identity()
    data = request.json
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""UPDATE tasks SET title=?, description=?, category=?, priority=?, status=?
                 WHERE id=? AND user_id=?""",
              (data["title"], data["description"], data["category"], data["priority"], int(data["status"]), task_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task updated"})


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@jwt_required()
def delete_task(task_id):
    user_id = get_jwt_identity()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (task_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task deleted"})


if __name__ == "__main__":
    app.run(debug=True)
