import socketserver,threading
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
    threading.Thread(target=tcp.serve_forever,daemon=True).start()
    threading.Thread(target=udp.serve_forever,daemon=True).start()
threading.Event().wait()
