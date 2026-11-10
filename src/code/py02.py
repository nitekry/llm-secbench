import os
import subprocess

from flask import Flask, abort, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/srv/thumbs/in"
OUT_DIR = "/srv/thumbs/out"
ALLOWED_SIZES = {"64", "128", "256"}
MAX_BYTES = 10 * 1024 * 1024


@app.route("/thumb", methods=["POST"])
def make_thumb():
    f = request.files.get("image")
    size = request.form.get("size", "128")
    if f is None or size not in ALLOWED_SIZES:
        abort(400)
    if request.content_length and request.content_length > MAX_BYTES:
        abort(413)

    name = os.path.basename(f.filename or "upload")
    src = os.path.join(UPLOAD_DIR, name)
    f.save(src)

    dst = os.path.join(OUT_DIR, f"{size}_{name}.png")
    cmd = f"convert '{src}' -resize {size}x{size} '{dst}'"  # @@VULN@@
    rc = subprocess.call(cmd, shell=True)  # @@VULN@@
    if rc != 0:
        abort(500)
    return send_file(dst, mimetype="image/png")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
