import r2pipe
size = 0
while True:
    size -= 1

    fd = open('in.txt', 'w')
    fd.write('{:d}\n1024'.format(size))
    fd.close()
    
    r = r2pipe.open('./alloca')
    r.cmd("e dbg.profile=alloca.rr2")
    r.cmd("doo") # reopen for debugging
    r.cmd('aa')

    r.cmd('db 0x080487d3')
    r.cmd('db 0x08048670')

    r.cmd('dc')
    ebp = r.cmd('dr ebp')
    ret = int(ebp, 16) + 4

    r.cmd('dc')
    edx = r.cmd('dr edx')
    cook = int(edx, 16)

    offset = ret - cook
    print('size:{:d}, {:d}'.format(size, offset))
    if offset == 0:
        exit()

