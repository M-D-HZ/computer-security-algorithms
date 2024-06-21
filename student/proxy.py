from mitmproxy import http

import sys
sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)
from implementation.encryption import aes  #, salsa


def request(flow: http.HTTPFlow) -> None:
    pass

    # TODO: Hack away


def response(flow: http.HTTPFlow) -> None:
    # Example: Change the title of the page
    flow.response.raw_content = flow.response.content.decode().replace("Flaskr", "Flaskr-Spoofed").encode()

    # TODO: Hack away
