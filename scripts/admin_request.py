#!/usr/bin/env python3
"""Send one authenticated request to an Unix-AGB admin socket."""
import json
import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(sys.argv[1])
    client.sendall((json.dumps({"token": sys.argv[2], "operation": "list", "operator": "lab"}) + "\n").encode())
    print(client.makefile("rb").readline().decode(), end="")
