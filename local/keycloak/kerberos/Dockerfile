FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-user python3 python3-gssapi && rm -rf /var/lib/apt/lists/*
COPY start.sh /fixture/start.sh
COPY ticket.py /fixture/ticket.py
RUN chmod 755 /fixture/start.sh
HEALTHCHECK --interval=1s --timeout=2s --retries=20 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18091/ready',timeout=1).read()"
ENTRYPOINT ["/fixture/start.sh"]
