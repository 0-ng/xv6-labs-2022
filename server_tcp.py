import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
addr = ('localhost', int(sys.argv[1]))
print('listening on %s port %s' % addr, file=sys.stderr)
sock.bind(addr)
sock.listen(5)

conn, address = sock.accept()     # 等待连接，此处自动阻塞
while True:     # 一个死循环，直到客户端发送‘exit’的信号，才关闭连接
    client_data = conn.recv(1024).decode()      # 接收信息
    print("来自%s的客户端向你发来信息：%s" % (address, client_data))
    if client_data == "exit":       # 判断是否退出连接
        break
    conn.sendall('server has received'.encode())    # 回馈信息给客户端
conn.close()    # 关闭连接



