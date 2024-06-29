import json
import hashlib

def generate_json_with_hashed_passwords(user_passwords, filename):
    hashed_user_passwords = {}
    for username, password in user_passwords.items():
        # Hash the password using SHA-256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_user_passwords[username] = hashed_password

    # Save JSON data to a file
    with open(filename, 'w') as json_file:
        json.dump(hashed_user_passwords, json_file, indent=4)

    return filename

if __name__ == "__main__":
    # Dictionary containing usernames and passwords
    user_passwords = {
        "amal": "3s9cf3466fF!",
        "user1": "password1",
        "user2": "password2",
        # Add more username-password pairs as needed
    }

    # Filename to save the JSON data
    filename = "user_passwords.json"

    saved_filename = generate_json_with_hashed_passwords(user_passwords, filename)
    print("JSON data saved to file:", saved_filename)
