import r2pipe
size = 0
while True:
    size += 1
    size  = 3564
    fd = open('in.txt', 'w')
    fd.write('{:d}\n1024'.format(size))
    fd.close()
    
    r = r2pipe.open('./alloca')
    r.cmd("e dbg.profile=alloca.rr2")
    r.cmd("doo") # reopen for debugging
    #r.cmd('aa')

    r.cmd('db 0x080487d3')
    r.cmd('db 0x08048670')
    r.cmd('db 0x08048838')

    r.cmd('dc')
    ebp = r.cmd('dr ebp')
    ret_addr = int(ebp, 16) + 4
    ret = r.cmd('pxw 4 @ {}'.format(hex(ret_addr)))[30:][:10]

    r.cmd('dc')
    edx = r.cmd('dr edx')
    cook = int(edx, 16)

    offset = ret_addr - cook
    print('size:{:d}, {:d}'.format(size, offset))

    #r.cmd('dc')
    #ret = r.cmd('pxw 4 @ esp')[30:][:10]
    #ret = int(ret, 16)
    #if ret != 0xf7d42b41:
    #    print('ret cambio!!!')
    #    print('antes:0xf7d42b41')
    #    print('ahora:' + hex(ret))
    #    exit()


    if offset == 0:
        exit()

