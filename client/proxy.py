import os
import traceback
from mitmproxy import http

import sys
sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)
from implementation.utils import get_preshared_key, encrypt, decrypt, write_error, get_headers_and_names
from implementation.authentication.mac import generate_mac_sha1, generate_mac_hmac, get_string_to_auth
from datetime import datetime
import json


# Check if the errors directory exists
if not os.path.exists('errors'):
    os.mkdir('errors')


def get_encryption_method() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["encryption"]["method"]

def get_authetication_method() -> str:
    with open('./config.json', 'r') as file:
        data = json.load(file)
    return data["mac"]["method"]
    
def authenticate_request(flow: http.HTTPFlow, method: str, key: str, nonce: str):
    header_names = get_headers_and_names(flow.request)
    placeholder_header = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key, nonce, header_names, "")
    flow.request.headers["Authorization"] = placeholder_header
    flow.request.headers["X-Authorization-Timestamp"] = str(int(datetime.now().timestamp()))

    string_to_auth = get_string_to_auth(flow.request)

    if method == "sha1":
        mac = generate_mac_sha1(string_to_auth, key, nonce)
    elif method == "sha512hmac":
        mac = generate_mac_hmac(string_to_auth, key, nonce)
    else:
        flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/plain",
                                                                    "date": datetime.now().strftime(
                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                    "connection": "close", "WWW-Authenticate": method})
        return

    header_value = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key, nonce, header_names, mac)
    flow.request.headers["Authorization"] = header_value

def authenticate_response(flow: http.HTTPFlow, method: str, key: str, nonce: str):
    auth_header = flow.request.headers.get("Authorization", "")

    parts = auth_header.split('mac="')
    original_mac = parts[1].split('"')[0]

    placeholder_header = auth_header.replace('mac="{}"'.format(original_mac), 'mac=""')
    flow.request.headers["Authorization"] = placeholder_header
    request_timestamp = int(flow.request.headers.get("X-Authorization-Timestamp", ""))
    current_time = int(datetime.now().timestamp())
    diff = int(current_time) - int(request_timestamp)
    if diff > 900:
        flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/plain",
                                                                    "date": datetime.now().strftime(
                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                    "connection": "close",
                                                                    "WWW-Authenticate": method})
        return

    string_to_auth = get_string_to_auth(flow.request)

    if method == "sha1":
        computed_mac = generate_mac_sha1(string_to_auth, key, nonce)
    elif method == "sha512hmac":
        computed_mac = generate_mac_hmac(string_to_auth, key, nonce)
    else:
        flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/plain",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": method})
        return

    if computed_mac != original_mac:
        flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/plain",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S GMT"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": method})
def request(flow: http.HTTPFlow) -> None:
    try:  # Do not edit this line
        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the falskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr

        encryption_method = get_encryption_method()
        auth_method = get_authetication_method()
        key = get_preshared_key()

        if 'Content-Encoding' in flow.request.headers:
            flow.request.headers['Content-Encoding'] = encryption_method
        else:
            flow.request.headers.insert(0, 'Content-Encoding', encryption_method)  # Headers are always strings
        if int(flow.request.headers.get('Content-Length', 0)) > 0:
            flow.request.raw_content = encrypt(flow.request.raw_content, key, 'abcdefghijklmnop', encryption_method)
            flow.request.set_content(flow.request.raw_content)

        authenticate_request(flow, auth_method, key, 'abcdefghijklmnop')

    except Exception as e:
        # Return an error reply to the client with the error message
        write_error(flow, 'Client side - Request:\n{}\n{}'.format(e, traceback.format_exc()))

def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    
    if "X-Authenticated-Id" in flow.response.headers:
        flow.response = http.Response.make(401, b"unauthenticated", {"Content-Type": "text/plain"})
        return
    
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the falskr website
            return
        

        encryption_method = get_encryption_method()
        auth_method = get_authetication_method()
        key = get_preshared_key()

        authenticate_response(flow, auth_method, key, 'abcdefghijklmnop')

        if 'Content-Encoding' in flow.response.headers:  # Checks if a header is present
            # Replaces the value of a header
            flow.response.headers['Content-Encoding'] = str(flow.response.headers['Content-Encoding']).replace(encryption_method, '')
        if int(flow.response.headers.get('Content-Length', 0)) > 0:
            flow.response.raw_content = decrypt(flow.response.content, key, 'abcdefghijklmnop', encryption_method)
            flow.response.set_content(flow.response.raw_content)


    except Exception as e:
        # Return an error reply to the client with the error message
        write_error(flow, 'Client side - Response:\n{}\n{}'.format(e, traceback.format_exc()))
