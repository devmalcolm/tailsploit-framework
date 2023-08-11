import socket
import pyaudio

# Set up audio playback
CHUNK_SIZE = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100

p = pyaudio.PyAudio()
stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK_SIZE)

# Set up socket connection
SERVER_IP = '0.0.0.0'
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, PORT))
server_socket.listen(1)

print("Server listening...")

connection, client_address = server_socket.accept()
print("Connected to:", client_address)

# Audio playback loop
try:
    while True:
        audio_chunk = connection.recv(CHUNK_SIZE)
        if not audio_chunk:
            break
        stream.write(audio_chunk)
finally:
    stream.stop_stream()
    stream.close()
    p.terminate()
    connection.close()
    server_socket.close()
