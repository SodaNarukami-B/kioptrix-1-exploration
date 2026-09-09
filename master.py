import socket
import struct
import datetime
import time

ADDR = "192.168.1.104";
PORT = 139;

def recv(sock):
    try:
        res = sock.recv(1024);
    except Exception as e:
        print(f"Cannot receive - {e}");
        return -1;

    for i in range(0, len(res), 16):
        print(res[i: i + 16]);

def send(sock: socket.socket, data):
    try: 
        sock.sendall(data);
    except Exception as e:
        print(f"Failed to send - {e}");
        return -1;

    return 0;

def get_conn():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    if not sock:
        print("Socket error");
        return -1;

    timeval = struct.pack("ll", 0, 200000);

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, timeval);
    # sock.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1);

    try:
        sock.connect((ADDR, PORT));
    except ConnectionError:
        print("Failed to connect");
        return -1;

    return sock;



def main():
    sock = get_conn()
    if sock == -1:
        return -1;

    # ------------------ Nbios session setup ----------------------
    packet = (
        b"\x81\x00\x00\x44\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x00\x20\x46\x44\x45\x50\x45\x45\x45\x42\x43"
        b"\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43"
        b"\x41\x43\x41\x43\x41\x43\x41\x00"
    );
    send(sock, packet);

    time.sleep(0.1);
    # ---------------------- Negotiate ----------------------------------

    packet = (
        b"\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x18\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x0c\x02NT LM 0.12\x00"
    );

    send(sock, packet);

    time.sleep(0.1)
    return 0;


if __name__ == "__main__":
    print(datetime.datetime.now());
    main();





