

import os
import socket
import ssl
import logging
import json
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(dotenv_path=os.getenv("SFTP_ENV_VAR"))

log_file_path = os.getenv('log_file_path')

# Global variable for the current username
current_username = ""

# Configure logging with username in format
class UserFilter(logging.Filter):
    def filter(self, record):
        record.username = current_username
        return True

logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format='%(asctime)s - %(username)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()
logger.addFilter(UserFilter())


def get_checksum_from_file(filename, checksum_file="checksums.json"):
    if os.path.exists(checksum_file):
        with open(checksum_file, "r") as f:
            checksums = json.load(f)
        return checksums.get(filename)
    return None


def calculate_checksum(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def send_file(conn, base_directory):
    try:
        # Receive username and filename from client
        username = current_username
        filename = conn.recv(1024).decode()

        # Create user-specific directory path
        user_directory = os.path.join(base_directory, username)
        file_path = os.path.join(user_directory, filename)

        if os.path.isfile(file_path):
            # Calculate the checksum of the file
            actual_checksum = calculate_checksum(file_path)

            # Get the expected checksum
            expected_checksum = get_checksum_from_file(filename)
            if expected_checksum is None:
                conn.sendall(b"Checksum not found")
                logging.error(f"Checksum for file '{filename}' not found.")
                return

            # Compare checksums
            if actual_checksum == expected_checksum:
                # Send success message to client
                conn.sendall(b"File is valid")

                # Send file size to client
                file_size = os.path.getsize(file_path)
                conn.sendall(str(file_size).encode())

                # Send file data to client
                with open(file_path, "rb") as file:
                    while True:
                        data = file.read(1024)
                        if not data:
                            break
                        conn.sendall(data)

                print(f"File '{filename}' sent successfully.")
                logging.info(f"File '{filename}' sent successfully.")
            else:
                conn.sendall(b"File checksum mismatch")
                logging.error(f"File checksum mismatch for file '{filename}'.")
        else:
            # Inform client that file was not found
            conn.sendall(b"File not found")
            logging.error(f"File '{filename}' not found.")
    except Exception as e:
        print(f"Error sending file: {e}")
        logging.error(f"Error sending file: {e}")


def update_checksum_file(filename, checksum, checksum_file="checksums.json"):
    # Load existing checksums
    if os.path.exists(checksum_file):
        with open(checksum_file, "r") as f:
            checksums = json.load(f)
    else:
        checksums = {}

    # Update the dictionary
    checksums[filename] = checksum

    # Save the updated checksums back to the file
    with open(checksum_file, "w") as f:
        json.dump(checksums, f, indent=4)

def receive_file(conn, base_directory):
    try:
        # Receive the username first
        username = current_username

        # Create user-specific directory
        user_directory = os.path.join(base_directory, username)
        if not os.path.exists(user_directory):
            os.makedirs(user_directory)

        filename = conn.recv(1024).decode()
        file_size = int(conn.recv(1024).decode())
        file_path = os.path.join(user_directory, filename)

        with open(file_path, "wb") as file:
            received_size = 0
            while received_size < file_size:
                data = conn.recv(1024)
                if not data:
                    break
                file.write(data)
                received_size += len(data)

        if received_size == file_size:
            actual_checksum = calculate_checksum(file_path)
            conn.sendall("File received successfully".encode())
            logging.info(f"File received: {file_path}")
            update_checksum_file(filename, actual_checksum)
        else:
            conn.sendall("File transfer incomplete".encode())
            logging.warning(f"File transfer incomplete: {file_path}")
    except FileNotFoundError:
        conn.sendall("File not found".encode())
        logging.error(f"Error receiving file: File not found: {file_path}")
    except Exception as e:
        conn.sendall(f"Error receiving file: {e}".encode())
        logging.error(f"Error receiving file: {e}")


def list_files(conn, base_directory):
    try:
        # Receive the command and username
        data = conn.recv(1024).decode()
        command = json.loads(data)
        username = command["username"]

        # Create user-specific directory path
        user_directory = os.path.join(base_directory, username)

        # List files in the user's directory
        if os.path.exists(user_directory):
            files = os.listdir(user_directory)
            conn.sendall(json.dumps(files).encode())
            logging.info(f"Listed files in directory: {user_directory}")
        else:
            conn.sendall(json.dumps([]).encode())  # Send an empty list if directory doesn't exist
            logging.warning(f"Directory not found: {user_directory}")
    except Exception as e:
        logging.error(f"Error listing files: {e}")
        conn.sendall(json.dumps([]).encode())  # Send an empty list on error

def load_user_passwords(filename):
    try:
        with open(filename, 'r') as json_file:
            return json.load(json_file)
    except FileNotFoundError:
        logging.error(f"User password file '{filename}' not found")
        return {}

def authenticate_user(conn):
    global current_username
    user_passwords = load_user_passwords('user_passwords.json')

    try:
        auth_info = conn.recv(1024).decode().split(":")
        username = auth_info[0]
        hashed_password = auth_info[1]

        logging.info(f"Attempting authentication for username: {username}")

        if username in user_passwords:
            if hashed_password == user_passwords[username]:
                conn.sendall("Authentication successful".encode())
                logging.info(f"Authentication successful for username: {username}")
                current_username = username  # Set the global username
                return True
            else:
                conn.sendall("Authentication failed: Invalid password".encode())
                logging.warning(f"Authentication failed for username: {username}. Invalid password.")
                return False
        else:
            conn.sendall("Authentication failed: Invalid username".encode())
            logging.warning(f"Authentication failed for username: {username}. Invalid username.")
            return False
    except Exception as e:
        print(f"Error during authentication: {e}")
        logging.error(f"Error during authentication: {e}")
        conn.sendall("Authentication failed: Error during authentication".encode())
        logging.error(f"Error during authentication: {e}")
        return False

def view_logs(conn):
    try:
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
            user_logs = [line for line in lines if f" - {current_username} - " in line]
            if user_logs:
                logs_to_send = "\n".join(user_logs)
                conn.sendall(logs_to_send.encode())
            else:
                conn.sendall(f"No logs found for {current_username}.".encode())
    except Exception as e:
        print(f"Error reading log file: {e}")
        logging.error(f"Error reading log file: {e}")
        conn.sendall(f"Error reading log file: {e}".encode())

def main():

    host = socket.gethostname()
    port = int(os.getenv('port'))
    totalclient = int(input('Enter number of clients: '))

    certfile = os.getenv('certfile')
    keyfile = os.getenv('keyfile')
    upload_directory = os.getenv('upload_directory')
    os.makedirs(upload_directory, exist_ok=True)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    logger = logging.getLogger()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(totalclient)

    while True:
        print('Waiting for clients to connect...')
        try:
            conn, addr = sock.accept()
            secure_conn = ssl_context.wrap_socket(conn, server_side=True)

            authenticated = authenticate_user(secure_conn)
            if not authenticated:
                secure_conn.close()
                continue

            print(f'Connected with client {addr}')

            while True:
                command = secure_conn.recv(1024).decode()
                logging.info(f"Received command: {command} from {addr}")

                if command == 'upload':
                    receive_file(secure_conn, upload_directory)
                elif command == 'download':
                    send_file(secure_conn, upload_directory)
                elif command == 'list':
                    list_files(secure_conn, upload_directory)
                elif command == 'logs':
                    view_logs(secure_conn)
                elif command == 'exit':
                    print(f"Client {addr} requested to exit. Closing connection.")
                    secure_conn.close()
                    break

        except Exception as e:
            print(f"Error occurred: {e}")
            logging.error(f"Error occurred: {e}")
            continue

    sock.close()

if __name__ == '__main__':
    main()
