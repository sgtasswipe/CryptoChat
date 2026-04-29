import socket
import threading
import sys
import os
import time
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# static salt so keys are the same
SALT = b"StaticSalt123456" # Must be at least 8 bytes
NONCE_SIZE = 12 # Standard for AES-GCM
                # Nonce is used to add a random bit of data to the start of each cipher text,
                # So the same text wont yield the same result 
                # This prevents pattern recognition 

def derive_key(password: str):
    return low_level.hash_secret_raw(
        secret=password.encode(),
        salt=SALT,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    )

def receive(sock, signal):
    while signal:
        try:
            # Buffer size increased to handle nonce + ciphertext
            data = sock.recv(2048)
            if not data:
                break
            
            # Extract nonce and ciphertext
            nonce = data[:NONCE_SIZE]
            ciphertext = data[NONCE_SIZE:]
            
            try:
                decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                print(f"\nMessage: {decrypted_data.decode('utf-8')}")
            except InvalidTag:
                print("\n[Error] Decryption failed: Invalid tag. The key might be incorrect or the data was tampered with.")
            except Exception as e:
                print(f"\n[Error] Decryption error: {e}")
                
        except Exception as e:
            print(f"\n[Error] Connection error: {e}")
            print("You have been disconnected from the server")
            break

# Get host and port
host_input = input("Host (leave blank for 127.0.0.1): ").strip()
host = host_input if host_input else '127.0.0.1'
if host.lower() == 'localhost':
    host = '127.0.0.1'

port = int(input("Port: "))

# Attempt connection to server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    key_exists = input("Has a key already been established? (y/n): ").lower() == 'y'
    
    udp_port = port + 1
    
    if not key_exists:
        # Get key from user
        user_password = input("Enter the chat secret key to create: ")
        raw_key = derive_key(user_password)
        
        print(f"[DEBUG] TCP Handshake successful. Sending new AES key via UDP to {host}:{udp_port}...")
        
        # Small delay to ensure server UDP thread is bound and listening
        time.sleep(0.2)
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            # Send twice to increase visibility in Wireshark
            udp_sock.sendto(raw_key, (host, udp_port))
            sent_bytes = udp_sock.sendto(raw_key, (host, udp_port))
            print(f"[DEBUG] Sent {sent_bytes} bytes via UDP to {host}:{udp_port}.")
            print(raw_key.hex())
    else:
        print("Requesting key from server...")
        sock.sendall(b"GET_KEY")
        raw_key = sock.recv(32)
        if raw_key == b"NO_KEY_FOUND":
            print("Server has no key established yet. You must create one.")
            user_password = input("Enter the chat secret key to create: ")
            raw_key = derive_key(user_password)
            
            print(f"[DEBUG] Sending new AES key via UDP to {host}:{udp_port}...")
            
            time.sleep(0.2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.sendto(raw_key, (host, udp_port))
                sent_bytes = udp_sock.sendto(raw_key, (host, udp_port))
                print(f"[DEBUG] Sent {sent_bytes} bytes via UDP.")
        else:
            print(f"Key received from server ({len(raw_key)} bytes).")
            
    aesgcm = AESGCM(raw_key)
        
except Exception as e:
    print(f"Could not make a connection to the server: {e}")
    input("Press enter to quit")
    sys.exit(0)

# Create new thread to wait for data
receiveThread = threading.Thread(target=receive, args=(sock, True))
receiveThread.start()

# Send data to server
while True:
    message = input("You: ")
    if not message:
        continue
        
    # Generate a unique nonce for every message
    nonce = os.urandom(NONCE_SIZE)
    
    # Encrypt the message
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    
    # Send nonce + ciphertext
    sock.sendall(nonce + ciphertext)
