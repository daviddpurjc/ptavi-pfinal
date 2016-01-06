#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Programa cliente que abre un socket a un servidor
"""

import socket
import sys
from lxml import etree

# Parte cliente del UA

config = sys.argv[1]
metodo = sys.argv[2]
fich = etree.parse(str(config))
raiz = fich.getroot()
USUARIO = raiz.find("account").attrib["username"]
IPproxy = raiz.find("regproxy").attrib["ip"]
PUERTO = raiz.find("uaserver").attrib["puerto"]
PUERTORTP = raiz.find("rtpaudio").attrib["puerto"]
PUERTOPROXY = raiz.find("regproxy").attrib["puerto"]
LINEack = 'ACK sip:'+receptor+' SIP/2.0\r\n'
LINEinv = 'INVITE sip:'+receptor+' SIP/2.0\r\n'+
'Content-Type: application/sdp\r\n\r\n'+'v=0\r\n'+'o='+USUARIO+' '+
IP+'\r\n'+'s=tomorrowland\r\n'+
't=0\r\n'+'m=audio '+PUERTORTP+'RTP\r\n'
LINEbye = 'BYE sip:'+receptor+' SIP/2.0\r\n'
LINEreg = 'REGISTER sip:'+USUARIO+':'+PUERTO+' SIP/2.0\r\n'+'Expires: '+expires

if not len(sys.argv) == 4:
    sys.exit("Usage: python uaclient.py config method option")
if metodo == 'INVITE'
    receptor = sys.argv[3]
    LINE = LINEinv
elif metodo == 'BYE'
    receptor = sys.argv[3]
    LINE = LINEbye
elif metodo == 'REGISTER'
    receptor = raiz.find("regproxy").attrib["ip"]
    LINE = LINEreg
    expires = sys.argv[3]
else:
    sys.exit("Usage: python uaclient.py config method option")


# Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
try:
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((IPproxy, PUERTOPROXY))
except:
    ## 20101018160243 Error: No server listening at 193.147.73 port 5555
    sys.exit("Error: No server listening")

print("Enviando: " + LINE)
my_socket.send(bytes(LINE, 'utf-8') + b'\r\n')
data = my_socket.recv(1024)
r = data.decode('utf-8')
print('Recibido -- ', r)

if r.startswith("SIP/2.0 401 Unauthorized"):
    LINEregAut = LINEreg+"Authorization: response="+#numeroaleatorio
    print("Enviando: " + LINEregAut)
    my_socket.send(bytes(LINEregAut, 'utf-8') + b'\r\n')
    data = my_socket.recv(5120)
    re = data.decode('utf-8')
    print('Recibido -- ', re)
elif r == "SIP/2.0 100 Trying\r\nSIP/2.0 180 Ring\r\nSIP/2.0 200 OK\r\n\r\n":
    print("Enviando: " + LINEack)
    my_socket.send(bytes(LINEack, 'utf-8') + b'\r\n')
    data = my_socket.recv(5120)
else:
    data = my_socket.recv(1024)
    rec = data.decode('utf-8')
    print('Recibido -- ', rec)

print("Terminando socket...")


# Cerramos todo
my_socket.close()
print("Fin.")

