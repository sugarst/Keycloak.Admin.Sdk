import base64
import gssapi
from http.server import BaseHTTPRequestHandler, HTTPServer

# Owned loopback counterpart only. No request credentials or ticket bytes are logged.
class Tickets(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_GET(self):
        if self.path not in ("/ticket", "/ready"):
            self.send_error(404)
            return
        body = b"ready"
        if self.path == "/ticket":
            target = gssapi.Name("HTTP@localhost", name_type=gssapi.NameType.hostbased_service)
            context = gssapi.SecurityContext(name=target, mech=gssapi.OID.from_int_seq("1.3.6.1.5.5.2"), usage="initiate")
            body = base64.b64encode(context.step())
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("127.0.0.1", 18091), Tickets).serve_forever()
