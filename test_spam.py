import socket, json, time, hashlib

def run():
    s=socket.create_connection(('127.0.0.1',5555))
    s.sendall((json.dumps({'type':'nickname','name':'spammer','uid':'spammer1'})+'\n').encode('utf-8'))
    # read welcome
    try:
        print(s.recv(4096).decode('utf-8'))
    except Exception:
        pass
    msg = 'spamhello'
    fingerprint=hashlib.sha256(msg.encode('utf-8')).hexdigest()
    packet = {'type':'message','text':msg,'receiver_uid':'','timestamp':time.strftime('%Y-%m-%dT%H:%M:%S'), 'fingerprint':fingerprint}
    for i in range(6):
        s.sendall((json.dumps(packet)+'\n').encode('utf-8'))
        time.sleep(0.2)
    time.sleep(1)
    try:
        print('RESP:', s.recv(4096).decode('utf-8'))
    except Exception as e:
        print('recv err', e)
    s.close()

if __name__ == '__main__':
    run()
