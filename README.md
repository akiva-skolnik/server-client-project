# Client-Server Secure Communication Project

This project is developed as part of the course "Defensive programming 20937" by OpenU.
It implements the server in Python and the client in C++

## Features
- Handles client registration and login.
- Supports secure file transfers with encryption.
- Uses SQL for database management.
- Uses AES for encryption.
- Uses RSA for key exchange.

## Security concerns:
1. The AES key is stored in plain text in the database, and is not encrypted.
    This is a security concern, as anyone with access to the database and that can intercept the communication can decrypt the files.
2. The files from clients are stored as-is in the file system, and are not encrypted.
    This is a security concern, as anyone with access to the file system can read the files.
3. The client's saves its private key in plain text in the file system.
    This is a security concern, as anyone with access to the file system can read the private key.
4. The server does not implement any rate limiting.
    This is a security concern, as it can lead to a denial of service attack.
5. Middle Man Attack - someone can recieve the public key from the client and respond with AES key.
    From this moment he will be able to decrypt the client files.

## Protocol problems:
1. Payload size is 4 bytes long, and when sending a file, the content size is also 4 bytes, 
    so the max payload allowed is content_size(4) + file_name(255) + file_content(4 bytes long) = 259 bytes more than the max payload size.
    To resolve this, I ignored the payload size when receiving a file, and used the content size instead, as it is more accurate.
2. Path name size and file name size (which is part of the path) are both 255.
    To resolve this, I changed the path size, without any side effects.