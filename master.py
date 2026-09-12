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
    # ---------------------- Session setup -------------------------------
    packet = (
        b"\x00\x00\x00\x4c\xffSMB\x73\x00\x00\x00\x00\x18\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" 
        b"\x0d\xff\x00\x00\x00\xff\xff\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00unix\x00"
        b"samba\x00"
    )

    send(sock, packet);
    time.sleep(0.1);

    # -------------------------- Tree connect --------------------------------
    packet = ( 
        b"\x00\x00\x00\x46"  # NB

        b"\xffSMB\x75"       # protocol & command
        b"\x00\x00\x00\x00"  # status
        b"\x18\x00\x00"      # flag & flag2
        b"\x00\x00"          # pid high
        b"\x00\x00\x00\x00\x00\x00\x00\x00" # signature
        b"\x00\x00"          # reserved
        b"\x00\x00"          # tid
        b"\x00\x00"          # pid
        b"\x64\x00"          # uid
        b"\x00\x00"          # mid

        b"\x04"              # word count
        b"\xff\x00\x00\x00"  # andx
        b"\x00\x00"          # flags
        b"\x00\x00"          # password len

        b"\x14\x00"          # byte count
        b"\\\\192.168.1.104\\IPC$\x00"
        #b"IPC$\x00"        # service

    );

    send(sock, packet);
    time.sleep(0.1);

    # --------------------------- Create andx -------------------------------
    packet = (
        b"\x00\x00\x00\x56"   # NB

        b"\xffSMB\xa2"        # protocol & command
        b"\x00\x00\x00\x00"   # status
        b"\x18\x00\x00"       # flag & flag2
        b"\x00\x00"           # pid high
        b"\x00\x00\x00\x00\x00\x00\x00\x00" # signature
        b"\x00\x00"           # reserved
        b"\x01\x00"           # tid
        b"\x00\x00"           # pid
        b"\x64\x00"           # uid
        b"\x00\x00"           # mid

        b"\x18"               # word count
        b"\xff\x00\x00\x00"   # andx
        b"\x05\x00"           # name len
        b"\x00\x00\x00\x00"   # flag
        b"\x00\x00\x00\x00"   # fid
        b"\x00\x00\x00\x00"   # desired access
        b"\x00\x00\x00\x00\x00\x00\x00\x00" # allocation size
        b"\x00\x00\x00\x00"   # ext attributes
        b"\x00\x00\x00\x00"   # share access
        b"\x00\x00\x00\x00"   # create disposition
        b"\x02\x00\x00\x00"   # create options
        b"\x02\x00\x00\x00"   # impersonation
        b"\x00"               # security flag

        b"\x05\x00"
        b"soda\x00"
    )

    send(sock, packet);
    time.sleep(0.1);

    return 0;


if __name__ == "__main__":
    print(datetime.datetime.now());
    main();





