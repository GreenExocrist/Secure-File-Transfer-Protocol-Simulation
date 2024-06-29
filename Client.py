import socket
import ssl
import os
import logging
import hashlib
import json
from tkinter import Tk, filedialog, messagebox, Label, Entry, Button, Text, Scrollbar, END, Frame
from tkinter import ttk
import getpass
from dotenv import load_dotenv
from threading import Thread

# Load environment variables from .env file
load_dotenv(dotenv_path=os.getenv("SFTP_ENV_VAR"))

log_file_path_client = os.getenv("log_file_path_client")

# Global variable for username
current_username = ""

# Configure logging with username in format
class UserFilter(logging.Filter):
    def filter(self, record):
        record.username = current_username
        return True

logging.basicConfig(
    filename=log_file_path_client,
    level=logging.INFO,
    format='%(asctime)s - %(username)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()
logger.addFilter(UserFilter())

def update_text_widget(widget, message):
    widget.config(state='normal')
    widget.insert(END, message + '\n')
    widget.config(state='disabled')

def select_file():
    file_path = filedialog.askopenfilename()
    return file_path

def upload_file(sock, text_widget, progress_bar):
    try:
        filename = select_file()
        if not filename:
            update_text_widget(text_widget, "No file selected. Upload operation aborted.")
            logging.warning("No file selected. Upload operation aborted.")
            return

        sock.sendall(os.path.basename(filename).encode())
        file_size = os.path.getsize(filename)
        sock.sendall(str(file_size).encode())

        progress_bar['value'] = 0
        progress_bar['maximum'] = file_size

        with open(filename, "rb") as file:
            while True:
                data = file.read(1024)
                if not data:
                    break
                sock.sendall(data)
                progress_bar['value'] += len(data)
                progress_bar.update()

        update_text_widget(text_widget, "File sent successfully")
        logging.info(f"File sent: {filename}")

        response = sock.recv(1024).decode()
        update_text_widget(text_widget, response)

        if "File received successfully" in response:
            sock.sendall('list'.encode())
            list_files(sock, text_widget)
        else:
            update_text_widget(text_widget, "Upload failed or incomplete.")
            logging.warning("Upload failed or incomplete.")
    except FileNotFoundError:
        update_text_widget(text_widget, "File not found")
        logging.error(f"File not found: {filename}")
    except Exception as e:
        update_text_widget(text_widget, f"Error sending file: {e}")
        logging.error(f"Error sending file: {e}")

def download_file(sock, filename, text_widget, progress_bar):
    try:
        risky_extensions = ['.exe', '.bat', '.sh', '.zip', '.rar', '.7z', '.tar', '.gz', '.conf', '.ini', '.cfg', '.crt', '.key']
        file_extension = os.path.splitext(filename)[1].lower()

        if file_extension in risky_extensions:
            response = messagebox.askyesno("Potential Risk", "The file you are downloading may be risky. Do you want to proceed?")
            if not response:
                update_text_widget(text_widget, "Download operation aborted by user.")
                logging.warning("Download operation aborted by user.")
                return

        sock.sendall(filename.encode())

        server_response = sock.recv(1024).decode()
        if server_response == "File not found":
            update_text_widget(text_widget, "File not found on server.")
            logging.error(f"File '{filename}' not found on server.")
            return
        elif server_response == "Checksum not found":
            update_text_widget(text_widget, "Checksum not found on server.")
            logging.error(f"Checksum for file '{filename}' not found on server.")
            return
        elif server_response == "File checksum mismatch":
            update_text_widget(text_widget, "File checksum mismatch. The file may be corrupted or tampered with.")
            logging.warning(f"File checksum mismatch for file '{filename}'.")
            return
        elif server_response != "File is valid":
            update_text_widget(text_widget, "Unknown error from server.")
            logging.error(f"Unknown error from server: {server_response}")
            return

        file_size = int(sock.recv(1024).decode())
        received_size = 0
        data_buffer = b""

        progress_bar['value'] = 0
        progress_bar['maximum'] = file_size

        while received_size < file_size:
            data = sock.recv(1024)
            if not data:
                break
            data_buffer += data
            received_size += len(data)
            progress_bar['value'] += len(data)
            progress_bar.update()

        if received_size == file_size:
            default_save_directory = os.path.join(os.path.expanduser('~'), 'Downloads')

            if file_extension in risky_extensions:
                save_directory = default_save_directory
            else:
                save_directory = filedialog.askdirectory(title="Select Directory to Save File")

            if save_directory:
                file_path = os.path.join(save_directory, filename)
                with open(file_path, "wb") as file:
                    file.write(data_buffer)
                update_text_widget(text_widget, f"File '{filename}' downloaded successfully to '{save_directory}'.")
                logging.info(f"File '{filename}' downloaded successfully to '{save_directory}'.")
            else:
                update_text_widget(text_widget, "No directory selected. Download operation aborted.")
                logging.warning("Download operation aborted due to no directory selection.")
        else:
            update_text_widget(text_widget, "Download incomplete.")
            logging.warning(f"Download incomplete for file '{filename}'.")
    except ValueError as ve:
        update_text_widget(text_widget, f"Value error: {ve}")
        logging.error(f"Value error: {ve}")
    except OSError as oe:
        update_text_widget(text_widget, f"OS error: {oe}")
        logging.error(f"OS error: {oe}")
    except Exception as e:
        update_text_widget(text_widget, f"Error downloading file: {e}")
        logging.error(f"Error downloading file: {e}")

def list_files(sock, text_widget):
    try:
        command = {"command": "list", "username": current_username}
        sock.sendall(json.dumps(command).encode())

        data = sock.recv(1024).decode()
        if data:
            files = json.loads(data)
            update_text_widget(text_widget, f"Files in directory: {files}")
            logging.info(f"Listed files in directory")
        else:
            update_text_widget(text_widget, "Error: Received empty data")
            logging.error("Error: Received empty data")
    except json.JSONDecodeError as e:
        update_text_widget(text_widget, f"Error listing files: {e}")
        logging.error(f"Error listing files: {e}")

def view_logs(text_widget):
    try:
        with open(log_file_path_client, 'r') as log_file:
            lines = log_file.readlines()
            user_logs = [line for line in lines if f" - {current_username} - " in line]
            if user_logs:
                update_text_widget(text_widget, f"Logs for {current_username}:")
                for log in user_logs:
                    update_text_widget(text_widget, log.strip())
            else:
                update_text_widget(text_widget, f"No logs found for {current_username}.")
    except Exception as e:
        update_text_widget(text_widget, f"Error reading log file: {e}")
        logging.error(f"Error reading log file: {e}")

def authenticate_user(sock, username, password, text_widget):
    global current_username
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        auth_info = f"{username}:{hashed_password}"
        sock.sendall(auth_info.encode())
        auth_result = sock.recv(1024).decode()

        if "Authentication successful" in auth_result:
            update_text_widget(text_widget, auth_result)
            logging.info("Authentication successful")
            current_username = username
            return True
        else:
            update_text_widget(text_widget, auth_result)
            logging.warning("Authentication failed")
            return False
    except Exception as e:
        update_text_widget(text_widget, f"Error during authentication: {e}")
        logging.error(f"Error during authentication: {e}")
        return False

def start_client():
    host = os.getenv("host")
    port = int(os.getenv("port"))
    certfile = os.getenv("certfile")
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certfile)

    def run_client():
        with socket.create_connection((host, port)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=host) as secure_sock:
                root = Tk()
                root.title("FTPS Client")

                def on_authenticate():
                    username = entry_username.get()
                    password = entry_password.get()
                    if authenticate_user(secure_sock, username, password, text_widget):
                        button_upload.config(state='normal')
                        button_download.config(state='normal')
                        button_list.config(state='normal')
                        button_view_logs.config(state='normal')
                        button_exit.config(state='normal')
                        entry_filename.config(state='normal')

                def on_upload():
                    secure_sock.sendall('upload'.encode())
                    upload_file(secure_sock, text_widget, progress_bar_upload)

                def on_download():
                    filename = entry_filename.get()
                    if filename:
                        secure_sock.sendall('download'.encode())
                        download_file(secure_sock, filename, text_widget, progress_bar_download)
                    else:
                        update_text_widget(text_widget, "Please enter a filename to download.")

                def on_list():
                    secure_sock.sendall('list'.encode())
                    list_files(secure_sock, text_widget)

                def on_view_logs():
                    view_logs(text_widget)

                def on_exit():
                    secure_sock.sendall('exit'.encode())
                    root.destroy()

                frame_auth = Frame(root)
                frame_auth.pack(pady=10)

                Label(frame_auth, text="Username:").grid(row=0, column=0, padx=5, pady=5)
                entry_username = Entry(frame_auth)
                entry_username.grid(row=0, column=1, padx=5, pady=5)

                Label(frame_auth, text="Password:").grid(row=1, column=0, padx=5, pady=5)
                entry_password = Entry(frame_auth, show="*")
                entry_password.grid(row=1, column=1, padx=5, pady=5)

                button_login = Button(frame_auth, text="Login", command=on_authenticate)
                button_login.grid(row=2, columnspan=2, pady=5)

                frame_ops = Frame(root)
                frame_ops.pack(pady=10)

                button_upload = Button(frame_ops, text="Upload File", state='disabled', command=on_upload)
                button_upload.grid(row=0, column=0, padx=5, pady=5)

                progress_bar_upload = ttk.Progressbar(frame_ops, orient='horizontal', length=200, mode='determinate')
                progress_bar_upload.grid(row=0, column=1, padx=5, pady=5)

                button_download = Button(frame_ops, text="Download File", state='disabled', command=on_download)
                button_download.grid(row=1, column=0, padx=5, pady=5)

                progress_bar_download = ttk.Progressbar(frame_ops, orient='horizontal', length=200, mode='determinate')
                progress_bar_download.grid(row=1, column=1, padx=5, pady=5)

                button_list = Button(frame_ops, text="List Files", state='disabled', command=on_list)
                button_list.grid(row=2, column=0, padx=5, pady=5)

                button_view_logs = Button(frame_ops, text="View Logs", state='disabled', command=on_view_logs)
                button_view_logs.grid(row=2, column=1, padx=5, pady=5)

                Label(frame_ops, text="Filename to download:").grid(row=3, column=0, padx=5, pady=5)
                entry_filename = Entry(frame_ops, state='disabled')
                entry_filename.grid(row=3, column=1, padx=5, pady=5)

                button_exit = Button(frame_ops, text="Exit", state='disabled', command=on_exit)
                button_exit.grid(row=4, columnspan=2, pady=5)

                text_widget = Text(root, state='disabled', width=80, height=20)
                text_widget.pack(pady=10)

                scrollbar = Scrollbar(root, command=text_widget.yview)
                scrollbar.pack(side='right', fill='y')
                text_widget.config(yscrollcommand=scrollbar.set)

                root.mainloop()

    Thread(target=run_client).start()

if __name__ == '__main__':
    start_client()
