# Secure File Transfer Protocol (SFTP) with Logging

This repository contains a secure file transfer protocol (SFTP) implementation using Python's socket and SSL libraries. The implementation includes a client and a server script, supporting secure file uploads, downloads, directory listing, and log viewing.

## Features

- **Secure Communication**: Uses SSL for encrypted communication between client and server.
- **File Upload**: Allows clients to securely upload files to the server.
- **File Download**: Allows clients to securely download files from the server.
- **Directory Listing**: Clients can view a list of files available on the server.
- **Logging**: Both client and server activities are logged for auditing and debugging purposes.
- **User Authentication**: Users must authenticate using a username and password before performing any file operations.

## Requirements

- Python 3.x
- Required Python libraries: `socket`, `ssl`, `os`, `logging`, `json`, `hashlib`, `getpass`, `tkinter` (for client)
- SSL certificate and key files for secure communication

## Installation

1. Clone the repository:

2. Ensure you have the required SSL certificate and key files in the specified directory:

3. Install required Python packages:


## Configuration

1. **Server Configuration**:
   - Update the `certfile` and `keyfile` paths in the `main()` function of `server.py` to point to your SSL certificate and key files.
   - Set the `upload_directory` to the path where you want to store uploaded files.

2. **Client Configuration**:
   - Update the `certfile` path in the `main()` function of `client.py` to point to your SSL certificate.

## Usage

1. **Start the Server**:

    ```sh
    python server.py
    ```

2. **Start the Client**:

    ```sh
    python client.py
    ```

3. **Client Commands**:
   - `upload`: Select a file to upload to the server.
   - `download`: Enter the filename to download from the server.
   - `list`: List all files available in the server's upload directory.
   - `logs`: View logs related to the current user's activities.
   - `exit`: Exit the client application.


## Logging

- **Client Logs**: Stored in `Server and Client Log/client.log`.
- **Server Logs**: Stored in `Server and Client Log/server.log`.
- Logs include timestamps, username, log level, and messages.

## User Authentication

- Users are authenticated using a username and hashed password stored in `user_passwords.json`.
- Passwords should be hashed using SHA-256 before storing them in the JSON file.

## Example `user_passwords.json`

```json
{
    "username1": "hashed_password1",
    "username2": "hashed_password2"
}


