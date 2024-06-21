import os
from mitmproxy import http
from implementation.encryption import aes, salsa

def example_function():
    pass


def write_error(flow: http.HTTPFlow, error: str) -> None:
    i = 0
    while os.path.exists('errors/error_{}.txt'.format(i)):
        i += 1
    open('errors/error_{}.txt'.format(i), 'w').write(error)
    flow.comment = 'ERROR: {}'.format(error)
    flow.response = http.Response.make(500, flow.comment[7:])


def get_preshared_key() -> str:
    with open('../implementation/preshared_key.txt', 'r') as f:
        return f.read()

def encrypt(content: bytes, key: str, nonce: str, method):
    if method == 'aes256cbc':
        return aes.encrypt(content, key, nonce)
    elif method == 'salsa20':
        return salsa.encrypt(content,key,nonce)

def decrypt(content: bytes, key: str, nonce: str, method):
    if method == 'aes256cbc':
        return aes.decrypt(content, key, nonce)
    elif method == 'salsa20':
        return salsa.decrypt(content,key,nonce)
    
def get_headers_and_names(request) -> (str, str):
    header_names = sorted([name.lower() for name in request.headers.keys()])
    header_names_str = ";".join(header_names)
    return header_names_str
