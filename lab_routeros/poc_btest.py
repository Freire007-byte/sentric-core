import socket, struct, sys, time

R2 = "10.99.99.2"
CTRL = 2000
MY_IP = "10.99.99.3"

def attempt(field_off, do_auth=True):
    my_udp = 40000 + field_off
    try:
        s = socket.create_connection((R2, CTRL), timeout=8)
    except Exception as e:
        print("off %d: connect falhou: %s" % (field_off, e))
        return 0
    s.settimeout(6)
    try:
        greet = s.recv(64)
    except Exception:
        greet = b""
    extra = bytearray(10)
    extra[field_off:field_off+2] = struct.pack("<H", my_udp)
    msg = b"\x00\x02\x01\x14" + struct.pack("<H", 1500) + bytes(extra)
    try:
        s.sendall(msg)
        resp = s.recv(64)
    except Exception:
        resp = b""
    if do_auth:
        try:
            s.sendall(b"\x27admin\x00" + bytes(range(32)))
        except Exception:
            pass
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        u.bind((MY_IP, my_udp))
    except Exception as e:
        print("off %d: bind falhou: %s" % (field_off, e))
        s.close()
        return 0
    u.settimeout(4)
    got = 0
    first = b""
    try:
        while True:
            d, addr = u.recvfrom(65535)
            if got == 0:
                first = d
            got += 1
    except socket.timeout:
        pass
    u.close()
    s.close()
    print("off %d: UDP recebidos=%d porta=%d greet=%s resp=%s" % (
        field_off, got, my_udp, greet[:4].hex(), resp[:4].hex()))
    if got:
        print("  PRIMEIRO PACOTE (%d bytes): %s" % (len(first), first[:48].hex()))
    return got

total = 0
for off in range(0, 10, 2):
    total += attempt(off)
print("TOTAL UDP:", total)
