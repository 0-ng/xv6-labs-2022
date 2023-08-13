import socket
import sys
import time
import threading

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
addr = ('localhost', int(sys.argv[1]))
print('listening on %s port %s' % addr, file=sys.stderr)
sock.bind(addr)

while True:
    sock, addr = s.accept()
    data = sock.recv(1024)
    print(data)
    # sock.close()
# time.sleep(10)

# while True:
#     sock, addr = s.accept()
#     # print("accept: " + str(addr))
#     t = threading.Thread(target=tcplink, args=(sock, addr))
#     t.start()


