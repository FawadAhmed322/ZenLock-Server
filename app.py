from flask import Flask, request, jsonify, session
from tinydb import TinyDB, Query
import bcrypt
import jwt
import datetime
from dotenv import load_dotenv
import os
import secrets

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set Flask's secret key from .env file
app.secret_key = os.getenv('SECRET_KEY')

# Initialize TinyDB and specify the JSON file to store data
db = TinyDB('database.json')
users_table = db.table('users')
passwords_table = db.table('passwords')

# JWT configuration loaded from .env file

JWT_SECRET = os.getenv('JWT_SECRET')
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 30 * 24 * 60 * 60  # Token expiration time (in seconds)

@app.route('/')
def index():
    return "Welcome to the Flask and TinyDB app!", 200

# Route to sign up a new user
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # Check if the user already exists
    User = Query()
    existing_user = users_table.get(User.email == email)
    
    if existing_user:
        return jsonify({'message': 'User already exists!'}), 409  # Conflict
    
    # Generate a separate salt for the user
    user_salt = secrets.token_hex(16)  # Generates a 16-byte (32 characters) hex string
    
    # Hash the password before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Insert the new user into the TinyDB table
    users_table.insert({
        'email': email,
        'password': hashed_password.decode('utf-8'),
        'user_salt': user_salt  # Store the user's unique salt
    })
    
    return jsonify({'message': 'User signed up successfully!'}), 201  # Created

# Route to sign in a user and generate a JWT
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # Find the user in the TinyDB table
    User = Query()
    user = users_table.get(User.email == email)
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        }
        token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        
        # Return the token and the user's unique salt
        return jsonify({'token': token, 'salt': user['user_salt']}), 200  # OK
    else:
        return jsonify({'message': 'Invalid email or password!'}), 401  # Unauthorized

# Decorator to protect routes with JWT authentication
def token_required(f):
    def wrapper(*args, **kwargs):
        token = None

        # Check if the token is provided in the headers and correctly formatted
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split(" ")
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
            else:
                return jsonify({'message': 'Invalid authorization header format!'}), 401  # Unauthorized

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401  # Unauthorized

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user = data['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401  # Unauthorized
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401  # Unauthorized

        return f(current_user, *args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper

# Route to add a new password entry (requires JWT authentication)
@app.route('/add_password', methods=['POST'])
@token_required
def add_password(current_user):
    data = request.get_json()
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')
    
    # Insert the new password entry into the TinyDB table
    passwords_table.insert({
        'website': website,
        'username': username,
        'password': password
    })
    
    return jsonify({'message': 'Password added successfully!'}), 201  # Created

# Route to retrieve a password entry by website (requires JWT authentication)
@app.route('/get_password', methods=['GET'])
@token_required
def get_password(current_user):
    website = request.args.get('website')
    Password = Query()
    entry = passwords_table.get(Password.website == website)
    
    if entry:
        return jsonify({
            'website': entry['website'],
            'username': entry['username'],
            'password': entry['password']
        }), 200  # OK
    else:
        return jsonify({'message': 'No entry found for the specified website'}), 404  # Not Found

@app.route('/validate_token', methods=['GET'])
@token_required
def validate_token(current_user):
    return jsonify({'message': 'Token is valid!', 'user': current_user}), 200  # OK

if __name__ == '__main__':
    app.run(debug=True)
