import json
from werkzeug.security import generate_password_hash
import uuid

def create_admin_user(username, password):
    try:
        # Try to load existing users
        with open('users.json', 'r') as f:
            users = json.load(f)
            if not isinstance(users, list):
                users = []
    except (FileNotFoundError, json.JSONDecodeError):
        users = []

    # Check if username already exists
    if any(user.get('username') == username for user in users):
        print(f"User '{username}' already exists!")
        return

    # Create new user
    new_user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'password_hash': generate_password_hash(password)
    }

    users.append(new_user)

    # Save updated users list
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)

    print(f"Admin user '{username}' created successfully!")

if __name__ == '__main__':
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")
    create_admin_user(username, password) 