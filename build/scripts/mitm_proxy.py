import socket
import struct

def proxy_mitm():
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_server.bind(('127.0.0.1', 3001))
    proxy_server.listen(1)
    
    atm_conn, atm_addr = proxy_server.accept()
    
    bank_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bank_conn.connect(('127.0.0.1', 3000))
        
    # Read Challenge from Bank 
    chal_len_data = bank_conn.recv(4)
    chal_len = struct.unpack('!I', chal_len_data)[0]
    chal_payload = b""
    while len(chal_payload) < chal_len:
        chal_payload += bank_conn.recv(chal_len - len(chal_payload))
    
    # Forward Challenge to ATM
    atm_conn.sendall(chal_len_data + chal_payload)
    
    # Read Request from ATM (Carefully ensuring full TCP frame arrives)
    req_len_data = atm_conn.recv(4)
    req_len = struct.unpack('!I', req_len_data)[0]
    req_payload = b""
    while len(req_payload) < req_len:
        req_payload += atm_conn.recv(req_len - len(req_payload))
        
    request_data = req_len_data + req_payload
    
    # Forward the valid Request to Bank
    bank_conn.sendall(request_data)
    
    # SIMULATE ATTACK / DROP: Sending RST to Bank abruptly
    print("\n[MITM Proxy] -> FORWARDED valid deposit of 50.00 to Bank!")
    print("[MITM Proxy] -> DROPPING TCP connection abruptly (Sending TCP RST)...")
    l_onoff = 1
    l_linger = 0
    bank_conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
    bank_conn.close()
    
    atm_conn.close()
    proxy_server.close()

if __name__ == '__main__':
    proxy_mitm()