#! /usr/bin/python3.6

import os
import socket
import sys

SOCK_FILE = "/var/run/sc-authd.socket"
PID_FILE = "/var/run/sc-authd.pid"


def verify_pan(pan_file: str) -> bool:
    """
    Fetches actual PAN (card number) hash from AuthD and compare with stored one
    Returns True if hashes matched
    """
    if not os.path.isfile(pan_file):
        return True

    if not os.path.exists(SOCK_FILE):
        print("Can't connect to sc auth daemon")
        return True
    
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK_FILE)
    sock.send(b"get_pan")
    pan = sock.recv(256).decode("utf-8")
    
    with open(pan_file, "rt") as pan_hash:
        if pan_hash.readline() == pan:
            return True
    return False


def read_pan(output: str or None) -> bool:
    """
    Fetches actual PAN hash from AuthD and if output is a string - writes it to corresponding file.
    Prints hash to otherwise
    """
    if not os.path.exists(SOCK_FILE):
        print("Can't connect to sc auth daemon")
        return False

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK_FILE)
    sock.send(b"get_pan")
    pan = sock.recv(256).decode("utf-8")

    if output is not None:
        with open(output, "wt") as pan_hash:
            pan_hash.write(pan)
    else:
        print(pan)
    return True


if __name__ == "__main__":
    # If user wants to read and save PAN
    if sys.argv[1] == "-c":
        param_output = sys.argv[2] \
            if len(sys.argv) > 2 \
            else None
        read_pan(param_output)
    else:
        param_pan_file = sys.argv[1]
        status = verify_pan(param_pan_file)

        # For obviousness
        if status:
            exit(0)
        exit(1)
