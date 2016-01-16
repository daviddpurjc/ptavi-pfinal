#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor proxy SIP
"""
import socket
import socketserver
import sys
import json
import time
import random
import xml.etree.ElementTree as ET
import hashlib

class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    """
    Echo server class
    """
    dic = {}
    direccion = ''
    campoexpire = ''
    listas = []
    ipUsuario = ''
    puertoUsuario = ''
    fechaReg = ''
    receptorUser = ''
    contador = 0
    lineaLog = ''
    response = ''
    nonce = ''
    deco = ''

    def handle(self):
        """ Metodo principal del servidorproxy. """
        # Comprueba que no tenemos usuarios registrados.
        if self.listas == []:
            self.json2registered()

        line = self.rfile.read()
        self.deco = line.decode('utf-8')
        
        if self.deco.startswith('REGISTER'):
            print(self.deco)
            resp = self.deco[self.deco.find("response=")+9:]
            self.response = resp.replace("\r\n","")
            trozo = self.deco[self.deco.find('sip:')+4:
                              self.deco.find('SIP')-1]
            self.puertoUsuario = trozo[trozo.find(':')+1:]
            self.direccion = trozo[:trozo.find(':')]
            self.lineaLog = " Received from "+str(self.client_address[0])+"\
:"+str(self.client_address[1])+": "+self.deco
            self.imprimeLog()
            if self.deco.find('Authorization:')!=-1:
                if self.compruebaUsuario() == 1:
                    self.ipUsuario = self.client_address[0]
                    self.fechaReg = time.time()
                    self.campoexpire = self.deco[self.deco.find('Expires:\
')+9:self.deco.find("\r\nAuth")]
                    self.dic[self.direccion] = self.client_address[0]
                    self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                    self.lineaLog = " Sent to \
"+str(self.client_address[0])+":"+str(self.puertoUsuario)+": "+"\
SIP/2.0 200 OK"
                    self.imprimeLog()
                    if self.campoexpire == '0\r\n':
                        del self.dic[self.direccion]
                    self.register2json()
                else:
                    self.nonce = ''
                    for i in range (21):
                        self.nonce += str(random.randint(0, 9))

                    self.guarda()
                    cad = "SIP/2.0 401 Unauthorized\r\n\
WWW Authenticate: Digest nonce="+self.nonce
                    self.lineaLog = " Sent to "+str(self.client_address[0])+"\
:"+str(self.puertoUsuario)+": "+cad
                    self.imprimeLog()
                    self.wfile.write(b"SIP/2.0 401 Unauthorized\r\n\
WWW Authenticate: Digest nonce="+self.nonce.encode('utf-8'))
            else:
                for i in range (21):
                    self.nonce += str(random.randint(0, 9))
                self.guarda()
                cad = "SIP/2.0 401 Unauthorized\r\nWWW Authenticate\
: Digest nonce="+self.nonce
                self.lineaLog = " Sent to "+str(self.client_address[0])+":\
"+str(self.puertoUsuario)+": "+cad
                self.imprimeLog()
                self.wfile.write(b"SIP/2.0 401 Unauthorized\r\nWWW \
Authenticate: Digest nonce="+self.nonce.encode('utf-8'))
        elif self.deco.startswith('INVITE') or \
             self.deco.startswith('BYE') or \
             self.deco.startswith('ACK'):
            self.receptorUser = self.deco[self.deco.find(":")+1:
                                          self.deco.find("SIP")-1]
            self.lineaLog =  " Received from "+str(self.client_address[0])+"\
:"+str(self.client_address[1])+": "+self.deco
            self.imprimeLog()
            for diccionario in self.listas:
                if diccionario['address'] == self.receptorUser and \
                   diccionario['expires'] >= \
                   time.strftime('%Y-%m-%d %H:%M:%S',
                                 time.gmtime(time.time())):
                    self.contador += 1
                    direc = self.deco[self.deco.find('p:')+2:
                                      self.deco.find(' ')]
                    IPdestino = diccionario['ip']
                    PUERTOdestino = diccionario['puerto']
                    my_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_DGRAM)
                    my_socket.setsockopt(socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)
                    my_socket.connect((IPdestino, int(PUERTOdestino)))
                    self.cabeceraProxy()
                    print("Enviando: " + self.deco)
                    self.lineaLog =  " Sent to "+str(IPdestino)+":\
"+str(PUERTOdestino)+": "+self.deco
                    self.imprimeLog()
                    my_socket.send(bytes(self.deco, 'utf-8') + b'\r\n')
                    try:
                        data = my_socket.recv(1024)
                        r = data.decode('utf-8')
                        print('Recibido -- ', r)
                        self.lineaLog =  " Received from "+str(IPdestino)+"\
:"+str(PUERTOdestino)+": "+r
                        self.imprimeLog()
                        if r.startswith("SIP/2.0 100") or \
                           r.startswith("SIP/2.0 200"):
                            self.lineaLog =  " Sent to \
"+str(self.client_address[0])+":"+str(self.client_address[1])+": "+r
                            self.imprimeLog()
                            self.wfile.write(data)
                    except:
                        self.wfile.write(b"Error: no server listening.")
            if self.contador == 0:
                self.lineaLog =  " Sent to "+str(self.client_address[0])+":\
"+str(self.client_address[1])+":SIP/2.0 404 User Not Found\r\n"
                self.imprimeLog()
                self.contador = 0
                self.wfile.write(b"SIP/2.0 404 User Not Found\r\n")

        else:
            self.lineaLog =  " Sent to "+str(self.client_address[0])+":\
"+str(self.client_address[1])+": "+self.deco
            self.imprimeLog()
            self.wfile.write("SIP/2.0 405 Method Not Allowed")


    def register2json(self):
        """ Gestionamos los usuarios registrados"""
        expira = time.strftime('%Y%m%d%H%M%S',
                               time.gmtime(int(self.campoexpire)+time.time()))
        dicc2 = {'address':self.direccion,'ip':self.ipUsuario,
                 'puerto':self.puertoUsuario,
                 'fecha':self.fechaReg,'expires': expira,}
        # Recorremos la lista de listas de usuarios para que si ya
        # existía el usuario, borremos su informacion,
        # que será actualizada con su nuevo valor de expiración.
        for diccionario in self.listas:
            if diccionario['address'] == self.direccion:
                self.listas.remove(diccionario)
        self.listas.append(dicc2)
        # Comprobamos la expiracion de los usuarios registrados,
        # y si alguno ha caducado lo borramos.
        for diccionario in self.listas:
            if diccionario['expires'] <= time.strftime('%Y\
%m%d%H%M%S',time.gmtime(time.time())):
                self.listas.remove(dicc2)
        json.dump(self.listas, open(FICHEROREG,'w'), sort_keys=True,
                  indent=4, separators=(',', ': '))

    def json2registered(self):
        # Comprueba si existe un fichero json para usarlo
        # como lista de usuarios registrados.
        try:
            self.listas = json.load(open(FICHEROREG,'r'))
        except:
            pass

    def imprimeLog(self):
        lineaSinSaltos = self.lineaLog.replace("\r\n"," ")
        log = open(FICHEROLOG,'a')
        log.write(time.strftime('%Y%m%d%H%M%S', 
                  time.gmtime(time.time()))+lineaSinSaltos+"\r\n")
        log.close()

    def guarda(self):
        logg = open("nonce.txt",'w')
        logg.write(self.nonce)
        logg.close()

    def cabeceraProxy(self):
        proxy = "Via: SIP/2.0/UDP "+IP+":"+PUERTO+";branch=z0hG5bKmp28a"
        if self.deco.startswith("INVITE"):
            linea = self.deco[:self.deco.find("Content-Type")]
            linea2 = self.deco[self.deco.find("Content-Type"):]
            self.deco = linea+proxy+"\r\n"+linea2
        else:
            linea = self.deco[:self.deco.find("\r\n")]
            self.deco = linea+"\n"+proxy

    def compruebaUsuario(self):
        m = hashlib.md5()
        bibi = open(CONTRASEÑAS,'r')
        for line in bibi:
            if line.startswith(self.direccion):
                contraseña = line[line.find(",")+1:line.find(";")]

        logo = open("nonce.txt",'r')
        self.nonce = logo.readline()
        nonceB = self.nonce.encode('utf-8')
        passwdB = contraseña.encode('utf-8')
        m.update(passwdB + nonceB)
        generado = m.hexdigest()
        if generado == self.response:
            return 1
        else:
            return 0

if __name__ == "__main__":
    # Creamos servidor de eco y escuchamos
    if len(sys.argv) != 2:
        sys.exit("Usage: python uaserver.py config")

    try:
        config = sys.argv[1]
        fich = ET.parse(str(config))
        raiz = fich.getroot()
        CONTRASEÑAS = raiz.find("database").attrib["passwdpath"]
        PUERTO = raiz.find("server").attrib["puerto"]
        NOMBRE = raiz.find("server").attrib["name"]
        IP = raiz.find("server").attrib["ip"]
        FICHEROLOG = raiz.find("log").attrib["path"]
        FICHEROREG = raiz.find("database").attrib["path"]
        serv = socketserver.UDPServer(('', int(PUERTO)),
                                       SIPRegisterHandler)
        print("Server "+NOMBRE+" listening at port "+PUERTO+"...")
        serv.serve_forever()
    except:
        sys.exit("Usage: python uaserver.py config")
