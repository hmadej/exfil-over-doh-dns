from dnslib.server import *
from dnslib.intercept import *
import hashlib, random, os

d = 139738284403078213458313682404757596911867038351023982603401085733576630181101409549152803132332513605515036772262923329
n = 172832441894998260376220012196504623107426809480060512025867051243862591841142762389754856720075168799498705818668742751
block_size = len(str(n))//4
if (block_size * 4 <= len(str(n))):
    block_size += 1


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


def check_padding(string, pad):
  rev_string = list(reversed(string))
  n = int(pad)
  if n > len(string):
    return False

  return all([rev_string[i] == pad for i in range(n)])


def num_to_bytes(n):
  if n == 0:
    return b'\x00'
  
  txt_num = str(n)
  if len(txt_num) == 3:
    txt_num = '000'*31 + txt_num 
    num_str = [txt_num[i:i+3] for i in range(0, len(txt_num), 3)]
  else:
    pad = (3 - (len(txt_num) % 3)) if len(txt_num) % 3 != 0 else 0
    txt_num = '0'*pad + txt_num
    num_str = [txt_num[i:i+3] for i in range(0, len(txt_num), 3)][:-1]
    if check_padding(num_str, num_str[-1]):
      n = int(num_str[-1])
      if n != 0:
        num_str = num_str[:-n]


  return b"".join(int(n).to_bytes(1, 'little') for n in num_str)


files = dict()



q = DNSRecord.question("xfer.io")
logger = DNSLogger(prefix=False)
rate_limit_range = 5



DOMAIN='xfer'

class TransferResolver:
        def resolve(self,request,handler):
          status = 0
          reply = request.reply()
          req = (str(request.q.qname).split('.'))
          if handler.client_address[0] not in files:
            files[handler.client_address[0]] = dict()
          if req[-3] == 'xfer' and req[-2] == 'io':
            if len(req) > 5:
              hex_str = "".join(req[1:-3])
              decoded = rsa_ende_crypt(int(hex_str, 16), (d,n))
              plain_txt = num_to_bytes(decoded)
              files[handler.client_address[0]][int(req[0], 16)] = plain_txt
            else:
              files[handler.client_address[0]]['hash'] = "".join(req[:-3])
              hash = hashlib.sha256()
              file = files[handler.client_address[0]]
              with open(f'{handler.client_address[0]}', 'wb') as f:
                for i in range(len(file)-1):
                  if i in file:
                    f.write(file[i])
                    hash.update(file[i])
                  else:
                    pass # respond with missing seq number
              if hash.hexdigest() == file['hash']:
                status = 1
                print(f'hashes match! for file {handler.client_address[0]}')
                os.rename(handler.client_address[0], file['hash'])
                files[handler.client_address[0]] = dict()
              else:
                print(f'hashes did not match!')
  
          rate_limit = random.randint(0,rate_limit_range)
          reply.add_answer(*RR.fromZone(f"xfer.io. 60 A 1.2.{status}.{rate_limit}"))
          return reply


resolver = TransferResolver()
server = DNSServer(resolver,port=8053,address="localhost",tcp=False)
server.start()


  