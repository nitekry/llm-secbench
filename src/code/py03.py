import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DOC_ROOT = "/var/www/manuals"


class ManualHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path != "/manual":
            self.send_error(404)
            return

        doc = parse_qs(url.query).get("doc", [""])[0]
        if not doc.endswith(".pdf"):
            self.send_error(400, "only PDF manuals are served")
            return

        path = os.path.join(DOC_ROOT, doc)  # @@VULN@@
        try:
            with open(path, "rb") as fh:  # @@VULN@@
                data = fh.read()
        except OSError:
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), ManualHandler).serve_forever()
