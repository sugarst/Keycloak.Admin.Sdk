import base64
import gssapi
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def service_ticket():
    target = gssapi.Name("HTTP@localhost", name_type=gssapi.NameType.hostbased_service)
    context = gssapi.SecurityContext(name=target, mech=gssapi.OID.from_int_seq("1.3.6.1.5.5.2"), usage="initiate")
    ticket = context.step()
    if not ticket:
        raise RuntimeError("GSSAPI returned no initial token")
    return base64.b64encode(ticket)


# Owned loopback counterpart only. No request credentials or ticket bytes are logged.
class Tickets(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path not in ("/ticket", "/ready"):
            self.send_error(404)
            return
        try:
            ticket = service_ticket()
        except gssapi.exceptions.GSSError as error:
            print(f"Kerberos ticket generation failed: GSSAPI status {error.maj_code}/{error.min_code}", file=sys.stderr, flush=True)
            self.send_error(503, "Kerberos ticket unavailable")
            return
        except RuntimeError:
            print("Kerberos ticket generation failed: no initial token", file=sys.stderr, flush=True)
            self.send_error(503, "Kerberos ticket unavailable")
            return
        body = ticket if self.path == "/ticket" else b"ready"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("127.0.0.1", 18091), Tickets).serve_forever()
