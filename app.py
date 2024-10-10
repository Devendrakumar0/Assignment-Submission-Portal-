from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from bson import ObjectId

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/Assignment"  # Connecting to Local Host MongoDB
app.config['JWT_SECRET_KEY'] = 'u7XVZ9m#6CpS@3wPL&8Y*1lDgT0qB^NFHzK4VoJaMZj!EfhxR' 
mongo = PyMongo(app)
jwt = JWTManager(app)

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    # Checking if the email already exists in the database (for both users and admins)
    existing_user = mongo.db.users.find_one({'email': email})
    
    if existing_user:
        return jsonify(message="A user with this email already exists. Please use a different email."), 409  # 409 Conflict

    # Hash the password and saving user to MongoDB
    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({
        'email': email,
        'username': username,
        'password': hashed_password,
        'role': 'user'  # Assigning a role to the user
    })

    return jsonify(message="User registered successfully"), 201


# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if user and check_password_hash(user['password'], password) and user['role'] == 'user':
        access_token = create_access_token(identity={'email': email, 'role': user['role']})
        return jsonify(access_token=access_token), 200

    return jsonify(message="Bad email or password"), 401


# User Uploading Assignment
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_assignment():
    data = request.json
    user_id = get_jwt_identity()['email']  # Getting the current user's identity (email)
    
    # Fetching the task and admin data from the request
    task = data.get('task')
    admin_username = data.get('admin_username')  # Admin's username from request body
    admin_email = data.get('admin_email')  # Admin's email from request body

    if not task or not admin_username or not admin_email:
        return jsonify(message="Task, admin username, and admin email are required"), 400

    # Checking if the admin exists in the database
    admin = mongo.db.users.find_one({'username': admin_username, 'email': admin_email, 'role': 'admin'})
    
    if not admin:
        return jsonify(message="Admin not found with provided username and email"), 404

    # Saving assignment to MongoDB and get the inserted ID
    result = mongo.db.assignments.insert_one({
        'userId': user_id,  # Email of the user uploading the assignment
        'task': task,
        'admin_username': admin_username,  # Admin's username
        'admin_email': admin_email,  # Admin's email
        'submitted_at': datetime.now(),
        'status': 'pending'  # Initial status of the assignment
    })

    # Return the response with the assignment ID
    return jsonify(message="Assignment uploaded successfully", assignment_id=str(result.inserted_id)), 201 


# User fetching their own assignments
@app.route('/user/assignments', methods=['GET'])
@jwt_required()
def get_user_assignments():
    user_email = get_jwt_identity()['email']  # Getting the current user's email

    # Fetching assignments where the userId matches the user's email
    assignments = mongo.db.assignments.find({'userId': user_email})

    output = []
    for assignment in assignments:
        output.append({
            'id': str(assignment['_id']),  # Including the assignment ID
            'task': assignment['task'],
            'admin_username': assignment['admin_username'],
            'submitted_at': assignment['submitted_at'],
            'status': assignment['status']  # Adding the status of the assignment
        })

    # If there are no assignments, return an appropriate message
    if not output:
        return jsonify(message="No assignments found"), 404

    return jsonify(assignments=output), 200



# Geting All Admins
@app.route('/admins', methods=['GET'])
@jwt_required()
def get_all_admins():
    # Fetching all users with the role of 'admin'
    admins = mongo.db.users.find({'role': 'admin'})
    output = []
    for admin in admins:
        output.append({
            'username': admin['username']
        })
    return jsonify(admins=output), 200


# Admin Registration
@app.route('/admin/register', methods=['POST'])
def register_admin():
    data = request.json
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    # Checking if the email already exists in the database 
    existing_user = mongo.db.users.find_one({'email': email})
    
    if existing_user:
        return jsonify(message="An admin with this email already exists. Please use a different email."), 409  # 409 Conflict

    # Hashing the password and save admin to MongoDB
    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({
        'email': email,
        'username': username,
        'password': hashed_password,
        'role': 'admin'  # Assigning a role to the admin
    })

    return jsonify(message="Admin registered successfully"), 201


# Admin Login
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    admin = mongo.db.users.find_one({'email': email})

    if admin and check_password_hash(admin['password'], password)  and admin['role'] == 'admin':
        access_token = create_access_token(identity={'email': email, 'role': 'admin'})
        return jsonify(access_token=access_token), 200

    return jsonify(message="Bad email or password"), 401


# Admin Getting Their Tagged Assignments
@app.route('/admin/assignments', methods=['GET'])
@jwt_required()
def get_admin_assignments():
    admin_email = get_jwt_identity()['email']  # Getting the current admin's identity (email)
    
    # Fetching assignments for the admin based on their email
    assignments = mongo.db.assignments.find({'admin_email': admin_email})  
    
    output = []
    for assignment in assignments:
        output.append({
            'id': str(assignment['_id']),  # Including the assignment ID
            'userId': assignment['userId'],  # Fetching userId 
            'task': assignment['task'],
            'submitted_at': assignment['submitted_at'],
            'status': assignment['status']  # Adding the status of the assignment
        })
    
    return jsonify(assignments=output), 200


# Admin Accepting Assignment
@app.route('/assignments/<string:assignment_id>/accept', methods=['POST'])
@jwt_required()
def accept_assignment(assignment_id):
    mongo.db.assignments.update_one({'_id': ObjectId(assignment_id)}, {'$set': {'status': 'accepted'}})
    return jsonify(message="Assignment accepted successfully"), 200


# Admin Rejecting Assignment
@app.route('/assignments/<string:assignment_id>/reject', methods=['POST'])
@jwt_required()
def reject_assignment(assignment_id):
    mongo.db.assignments.update_one({'_id': ObjectId(assignment_id)}, {'$set': {'status': 'rejected'}})
    return jsonify(message="Assignment rejected successfully"), 200


if __name__ == '__main__':
    app.run(debug=True)
