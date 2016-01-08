#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Programa cliente que abre un socket a un servidor
"""
import json
import time
import socket
import sys
from lxml import etree

# Parte cliente del UA

config = sys.argv[1]
metodo = sys.argv[2]
fich = etree.parse(str(config))
raiz = fich.getroot()
expires = ''

if metodo == 'INVITE':
    receptor = sys.argv[3]
elif metodo == 'BYE':
    receptor = sys.argv[3]
elif metodo == 'REGISTER':
    receptor = raiz.find("regproxy").attrib["ip"]
    expires = sys.argv[3]
else:
    sys.exit("Usage: python uaclient.py config method option")


USUARIO = raiz.find("account").attrib["username"]
IP = raiz.find("uaserver").attrib["ip"]
IPproxy = raiz.find("regproxy").attrib["ip"]
PUERTO = raiz.find("uaserver").attrib["puerto"]
PUERTORTP = raiz.find("rtpaudio").attrib["puerto"]
PUERTOPROXY = raiz.find("regproxy").attrib["puerto"]
LINEack = 'ACK sip:'+receptor+' SIP/2.0\r\n'
LINEinv = 'INVITE sip:'+receptor+' SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\no='+USUARIO+' '+IP+'\r\ns=tomorrowland\r\nt=0\r\nm=audio '+PUERTORTP+'RTP\r\n'
LINEbye = 'BYE sip:'+receptor+' SIP/2.0\r\n'
LINEreg = 'REGISTER sip:'+USUARIO+':'+PUERTO+' SIP/2.0\r\n'+'Expires: '+expires

if not len(sys.argv) == 4:
    sys.exit("Usage: python uaclient.py config method option")
if metodo == 'INVITE':
    LINE = LINEinv
elif metodo == 'BYE':
    LINE = LINEbye
elif metodo == 'REGISTER':
    LINE = LINEreg



# Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
try:
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((IPproxy, int(PUERTOPROXY)))
except:
    ## 20101018160243 Error: No server listening at 193.147.73 port 5555
    sys.exit("Error: No server listening")

#log = open("logclient.txt",'r')
log = open("logclient.txt",'a')
log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+" Starting...\r\n")
log.close()

print("Enviando: " + LINE)
log = open("logclient.txt",'a')
log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+LINE+"\r\n")
log.close()
my_socket.send(bytes(LINE, 'utf-8') + b'\r\n')
data = my_socket.recv(1024)
r = data.decode('utf-8')
print('Recibido -- ', r)
log = open("logclient.txt",'a')
log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+r+"\r\n")
log.close()

if r.startswith("SIP/2.0 401 Unauthorized"):
    LINEregAut = LINEreg+"\r\nAuthorization: response=3949485"
    print("Enviando: " + LINEregAut)
    log = open("logclient.txt",'a')
    log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+LINEregAut+"\r\n")
    log.close()
    my_socket.send(bytes(LINEregAut, 'utf-8') + b'\r\n')
    data = my_socket.recv(5120)
    re = data.decode('utf-8')
    print('Recibido -- ', re)
    log = open("logclient.txt",'a')
    log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+re+"\r\n")
    log.close()
elif r == "SIP/2.0 100 Trying\r\nSIP/2.0 180 Ring\r\nSIP/2.0 200 OK\r\n\r\n":
    print("Enviando: " + LINEack)
    log = open("logclient.txt",'a')
    log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+LINEack+"\r\n")
    log.close()
    my_socket.send(bytes(LINEack, 'utf-8') + b'\r\n')
    data = my_socket.recv(5120)
else:
    data = my_socket.recv(1024)
    rec = data.decode('utf-8')
    print('Recibido -- ', rec)
    log = open("logclient.txt",'a')
    log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))+rec+"\r\n")
    log.close()

print("Terminando socket...")


# Cerramos todo
my_socket.close()
print("Fin.")

