import socket
import struct
import sys

def proxy_mitm(listen_port=3001, bank_port=3000):
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_server.bind(('127.0.0.1', listen_port))
    proxy_server.listen(1)
    print(f'[MITM Proxy] Listening on 127.0.0.1:{listen_port} and waiting for ATM...')
    
    atm_conn, atm_addr = proxy_server.accept()
    print('[MITM Proxy] ATM connected to proxy.')
    
    bank_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f'[MITM Proxy] Connecting to Bank at 127.0.0.1:{bank_port}...')
    bank_conn.connect(('127.0.0.1', bank_port))
    print('[MITM Proxy] Connected to Bank.')
        
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
    _listen = int(sys.argv[1]) if len(sys.argv) > 1 else 3001
    _bank   = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    proxy_mitm(_listen, _bank)