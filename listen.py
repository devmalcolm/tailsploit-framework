import socket
import pyaudio

# Set up audio capture
CHUNK_SIZE = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100

p = pyaudio.PyAudio()
stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK_SIZE)

# Set up socket connection
SERVER_IP = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))

# Audio streaming loop
try:
    while True:
        audio_chunk = stream.read(CHUNK_SIZE)
        client_socket.sendall(audio_chunk)
finally:
    stream.stop_stream()
    stream.close()
    p.terminate()
    client_socket.close()
