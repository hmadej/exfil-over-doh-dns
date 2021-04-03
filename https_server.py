from flask import Flask, request
from dnslib.server import *
app = Flask(__name__)

@app.route("/dns-query", methods=["GET"])
def default():
  name = request.args.get('name', default='', type=str)
  q = DNSRecord.question(name)
  return q.send("localhost", 8053, tcp=False)


if __name__ == "__main__":
  app.run(ssl_context='adhoc')
  

# 'https://cloudflare-dns.com/dns-query?name=example.com&type=A'