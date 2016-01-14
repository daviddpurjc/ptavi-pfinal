#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Programa cliente que abre un socket a un servidor
"""
import json
import time
import socket
import sys
import os
import xml.etree.ElementTree as ET
import hashlib

# Parte cliente del UA

config = sys.argv[1]
metodo = sys.argv[2]
fich = ET.parse(str(config))
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
PASSWD = raiz.find("account").attrib["passwd"]
ip = raiz.find("uaserver").attrib["ip"]
if ip == '':
    IP = "127.0.0.1"
else:
    IP = ip

IPproxy = raiz.find("regproxy").attrib["ip"]
PUERTO = raiz.find("uaserver").attrib["puerto"]
PUERTORTP = raiz.find("rtpaudio").attrib["puerto"]
PUERTOPROXY = raiz.find("regproxy").attrib["puerto"]
LINEack = 'ACK sip:'+receptor+' SIP/2.0\r\n'
LINEinv = 'INVITE sip:'+receptor+' SIP/2.0\r\nContent-Type: application\
/sdp\r\n\r\nv=0\r\no='+USUARIO+' '+IP+'\r\ns=tomorrowland\r\nt=\
0\r\nm=audio '+PUERTORTP+' RTP\r\n'
LINEbye = 'BYE sip:'+receptor+' SIP/2.0\r\n'
LINEreg = 'REGISTER sip:'+USUARIO+':'+PUERTO+' SI\
P/2.0\r\nExpires: '+expires+"\r\n"

if not len(sys.argv) == 4:
    sys.exit("Usage: python uaclient.py config method option")
if metodo == 'INVITE':
    LINE = LINEinv
elif metodo == 'BYE':
    LINE = LINEbye
elif metodo == 'REGISTER':
    LINE = LINEreg



# Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
my_socket.connect((IPproxy, int(PUERTOPROXY)))

FICHEROLOG = raiz.find("log").attrib["path"]
log = open(FICHEROLOG,'a')
log.write(time.strftime('%Y%m%d%H%M%S', 
                        time.gmtime(time.time()))+" Starting...\r\n")
log.close()
print("Enviando: " + LINE)
l = LINE.replace("\r\n"," ")
log = open(FICHEROLOG,'a')
log.write(time.strftime('%Y%m%d%H%M%S', 
                        time.gmtime(time.time()))+" "+l+"\r\n")
log.close()
my_socket.send(bytes(LINE, 'utf-8') + b'\r\n')
try:
    data = my_socket.recv(1024)
    r = data.decode('utf-8')
    print('Recibido -- ', r)
    l = r.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
except:
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
                            +" Error: No server listening at "+
                            IPproxy+" port "+PUERTOPROXY+"\r\n")
    log.close()
    sys.exit("Error: No server listening")

if r.startswith("SIP/2.0 401 Unauthorized"):
    # Recibe el nonce del proxy y genera el response
    m = hashlib.md5()
    nonce = r[r.find("nonce=")+6:]
    nonceB = nonce.encode('utf-8')
    passwdB = PASSWD.encode('utf-8')
    m.update(passwdB + nonceB)
    response = m.hexdigest()
    LINEregAut = LINEreg+"Authorization: response="+response
    print("Enviando: " + LINEregAut)
    l = LINEregAut.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
    my_socket.send(bytes(LINEregAut, 'utf-8') + b'\r\n')
    data = my_socket.recv(5120)
    re = data.decode('utf-8')
    print('Recibido -- ', re)
    l = re.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
elif r.startswith("SIP/2.0 100 Trying"):
    print("Enviando: " + LINEack)
    extraigoRTP = r[r.find("audio")+6:r.find("RTP")-1]
    l = LINEack.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
    my_socket.send(bytes(LINEack, 'utf-8') + b'\r\n')
    print("Vamos a ejecutar: ")
    print("./mp32rtp -i 127.0.0.1 -p "+extraigoRTP+" < cancion.mp3")
    os.system("./mp32rtp -i 127.0.0.1 -p "+extraigoRTP+" < cancion.mp3")
    data = my_socket.recv(5120)
elif r == "Error: no server listening at that direction":
    l = r.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
    sys.exit("Error: No server listening")
elif r.startswith("SIP/2.0 200"):
    sys.exit("Finalizando llamada.")
else:
    data = my_socket.recv(1024)
    rec = data.decode('utf-8')
    print('Recibido -- ', rec)
    l = rec.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
    print("Enviando: " + LINEack)
    l = LINEack.replace("\r\n"," ")
    log = open(FICHEROLOG,'a')
    log.write(time.strftime('%Y%m%d%H%M%S', 
                            time.gmtime(time.time()))+" "+l+"\r\n")
    log.close()
    my_socket.send(bytes(LINEbye, 'utf-8') + b'\r\n')

print("Terminando socket...")
log = open(FICHEROLOG,'a')
log.write(time.strftime('%Y%m%d%H%M%S', 
                        time.gmtime(time.time()))+" Finishing.\r\n")
log.close()


# Cerramos todo
my_socket.close()
print("Fin.")

