import socket,sys,json
port=int(sys.argv[1]);action=sys.argv[2];target=('10.203.1.1',port)
def tcp(s,data):
    s.sendall(data);out=b''
    while len(out)<len(data):
        d=s.recv(len(data)-len(out))
        if not d:raise RuntimeError('unexpected EOF')
        out+=d
    assert out==data
if action=='probe':
    s=socket.create_connection(target,timeout=1);tcp(s,b'tcp-echo-test'*100);s.close()
    u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(1);u.sendto(b'udp-echo-test',target);assert u.recv(4096)==b'udp-echo-test';u.close();print('tcp_udp_ok')
elif action=='blocked':
    ok=False
    try:
        s=socket.create_connection(target,timeout=.5);tcp(s,b'blocked');ok=True
    except (OSError,RuntimeError):pass
    assert not ok,'TCP was not blocked'
    u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(.5)
    try:u.sendto(b'blocked',target);u.recv(4096);raise AssertionError('UDP was not blocked')
    except OSError:pass
    print('tcp_udp_blocked')
elif action=='persistent':
    s=socket.create_connection(target,timeout=1);s.settimeout(.8);u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(.8)
    tcp(s,b'before');u.sendto(b'before',target);assert u.recv(1024)==b'before';print('ready',flush=True)
    for line in sys.stdin:
        if line.strip()=='blocked':
            failures=0
            try:tcp(s,b'during')
            except (OSError,RuntimeError):failures+=1
            u.sendto(b'during',target)
            try:u.recv(1024)
            except OSError:failures+=1
            assert failures==2,'existing TCP/UDP continued after pause';print('existing_blocked',flush=True)
        else:break
