import socket
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Variables for holding information about connections
connections = []
total_connections = 0
shared_key = None
NONCE_SIZE = 12

# Client class, new instance created for each connected client
# Each instance has the socket and address that is associated with items
# Along with an assigned ID and a name chosen by the client
class Client(threading.Thread):
    def __init__(self, socket, address, id, name, signal):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.id = id
        self.name = name
        self.signal = signal
    
    def __str__(self):
        return str(self.id) + " " + str(self.address)
    
    # Attempt to get data from client
    # If unable to, assume client has disconnected and remove him from server data
    # If able to and we get data back, print it in the server and send it back to every
    # client aside from the client that has sent it
    # .decode is used to convert the byte data into a printable string
    def run(self):
        global shared_key
        while self.signal:
            try:
                # Increased buffer size to handle encrypted packets (nonce + tag + ciphertext)
                data = self.socket.recv(2048)
                if not data:
                    print(f"Client {self.address} has closed the connection.")
                    break
                
                # Check for key request
                if data == b"GET_KEY":
                    if shared_key:
                        self.socket.sendall(shared_key)
                        print(f"Sent established key to client {self.id}")
                    else:
                        self.socket.sendall(b"NO_KEY_FOUND")
                        print(f"Client {self.id} requested key, but none established yet.")
                    continue

            except Exception as e:
                print(f"Client {self.address} error: {e}")
                break
            
            # Print encrypted hex representation for logging
            print(f"ID {self.id} (Encrypted): {data.hex()[:32]}...")
            
            # Always relay the original encrypted bytes to all other clients
            for client in connections:
                if client.id != self.id:
                    try:
                        client.socket.sendall(data)
                    except:
                        pass
        
        # Cleanup on exit
        self.signal = False
        if self in connections:
            connections.remove(self)
        self.socket.close()

# Wait for new connections
def newConnections(socket):
    while True:
        sock, address = socket.accept()
        global total_connections
        connections.append(Client(sock, address, total_connections, "Name", True))
        connections[len(connections) - 1].start()
        print("New connection at ID " + str(connections[len(connections) - 1]))
        total_connections += 1

# UDP listener for receiving the AES key
def udp_key_listener(host, port):
    global shared_key
    # Use port + 1 for UDP key exchange 
    udp_port = port + 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        try:
            # If host is empty, bind to all interfaces
            bind_addr = host if host else '0.0.0.0'
            udp_sock.bind((bind_addr, udp_port))
            print(f"[DEBUG] UDP Key Listener successfully bound to {bind_addr}:{udp_port}")
            while True:
                print(f"[DEBUG] UDP Key Listener waiting for data on port {udp_port}...")
                data, addr = udp_sock.recvfrom(32) # AES-256 key is 32 bytes
                if data:
                    shared_key = data
                    print(f"[SUCCESS] AES key received via UDP from {addr}. Key stored.")
        except Exception as e:
            print(f"[ERROR] UDP Key Listener error: {e}")

def main():
    # Get host and port
    host_input = input("Host (leave blank for 127.0.0.1): ").strip()
    host = host_input if host_input else '127.0.0.1'
    if host.lower() == 'localhost':
        host = '127.0.0.1'
        
    port = int(input("Port: "))

    # Create new server socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[DEBUG] TCP Server listening on {host}:{port}")

    # Create new thread to wait for connections
    newConnectionsThread = threading.Thread(target = newConnections, args = (sock,))
    newConnectionsThread.start()

    # Create new thread for UDP key exchange
    udpThread = threading.Thread(target = udp_key_listener, args = (host, port))
    udpThread.daemon = True # Allow server to exit even if this thread is running
    udpThread.start()
    
if __name__ == "__main__":
    main()
