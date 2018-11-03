import socket
import re

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c = s.connect(('pwnable.kr', 9007))

def sum(arrby):
    send = ''
    for i in arrby:
        send += str(i) + ' '
    send = send[:-1]
    s.send(send.encode() + b'\n')
    r = s.recv(1024)
    return int(r.decode('utf-8'))

def solve(arrby, C):
    print('');print(str(arrby))
    largo = len(arrby)
    if largo == 1:
        for i in range(C):
            s.send(str(arrby[0]).encode() + b'\n')
            s.recv(100)
        return
    mitad = largo // 2
    # sumo mitad
    suma = sum(arrby[mitad:])
    C -= 1
    if (suma % 2) == 1:
        # esta aca
        solve(arrby[mitad:],C)
    else:
        #esta en la otra mitad
        solve(arrby[:mitad],C)

def main():
    r = s.recv(1024 * 2)
    for i in range(100):
        r = s.recv(200)
        r = r.decode('utf-8')
        rta = re.search(r'N=(\d+) C=(\d+)', r)
        N = int(rta.group(1))
        C = int(rta.group(2))+1
        array = list(range(N))
        solve(array, C)
        print('Done: ' + str(i+1) )
    print(s.recv(1024))

if __name__ == '__main__':
    main()
