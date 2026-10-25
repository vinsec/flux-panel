import socketserver,threading,socket,os
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(65536)
            if not data:return
            self.request.sendall(data)
class UDP(socketserver.BaseRequestHandler):
    def handle(self):self.request[1].sendto(self.request[0],self.client_address)
for port in [19000,19001]:
    tcp=socketserver.ThreadingTCPServer(('0.0.0.0',port),TCP);tcp.daemon_threads=True
    udp=socketserver.ThreadingUDPServer(('0.0.0.0',port),UDP);udp.daemon_threads=True
    if os.getenv('FLUX_ECHO_ALLOW_FRAGMENT')=='1':udp.socket.setsockopt(socket.IPPROTO_IP,10,0)
    threading.Thread(target=tcp.serve_forever,daemon=True).start()
    threading.Thread(target=udp.serve_forever,daemon=True).start()
threading.Event().wait()
