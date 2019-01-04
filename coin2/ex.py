import socket
import re
import math
import itertools

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c = s.connect(('pwnable.kr', 9008))

def combinatoria(n, p):
    return math.factorial(n)//(math.factorial(p) * math.factorial(n-p))


def recv(s, num):
    return s.recv(num).decode('utf-8')

def sum(arrays):
    query = ''
    for arr in arrays:
        query += '-' + ' '.join(str(e) for e in arr)
    query = query[1:]
    s.send(query.encode() + b'\n')
    return [ int(x) for x in recv(s, 1024)[:-1].split('-') ]

def maxIter(N, C):
    total = 0
    for p in range(C):
        total += combinatoria(C, p)
        if total >= N:
            return p

def solve(N, C):
    #print(str(N) + ' ' + str(C))

    arrays = [[] for i in range(C)]
    num = 0
    for choises in range(1, 10):
        for positions in itertools.combinations(range(C), choises):
            if num == N:
                break
            for pos in positions:
                #print('agrego pos:' + str(pos) + ' num:' + str(num))
                arrays[pos].append(num)
            num += 1

    summed = sum(arrays)
    impares = []
    for i, summ in enumerate(summed):
        if summ % 2 == 1:
            impares.append(i)
    
    idx = impares.pop()
    for num in arrays[idx]:
        isInAll = True
        for impar in impares:
            if num not in arrays[impar]:
                isInAll = False
        if isInAll:
            return str(num)
    print('Failed!!')

def main():
    r = s.recv(1024 * 2)
    for i in range(100):
        r = recv(s, 200)
        rta = re.search(r'N=(\d+) C=(\d+)', r)
        N = int(rta.group(1))
        C = int(rta.group(2))
        solution = solve(N, C)
        s.send(solution.encode() + b'\n')
        print(recv(s, 200))
    print(recv(s, 200))

if __name__ == '__main__':
    main()
