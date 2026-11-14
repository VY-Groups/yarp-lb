"""Disposable loopback-only fixed-body backend for real oha CLI contract test."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/bench/1024", "/bench/4096"):
            self.send_error(404)
            return
        body=b'x'*int(self.path.rsplit('/',1)[1])
        self.send_response(200)
        self.send_header('Content-Type','application/octet-stream')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*_args):
        return

ThreadingHTTPServer(('127.0.0.1',18888),Backend).serve_forever()
