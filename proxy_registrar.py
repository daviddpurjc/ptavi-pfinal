#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor de eco en UDP simple
"""
import socket
import socketserver
import sys
import json
import time
from lxml import etree
from string import Template

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

    def handle(self):
        """ Metodo principal del servidorproxy. """
        # Comprueba que no tenemos usuarios registrados, y llama al metodo json2registered.
        if self.listas == []:
            self.json2registered()
        # Escribe dirección y puerto del cliente (de tupla client_address)
        #print (self.client_address)
        line = self.rfile.read()
        deco = line.decode('utf-8')
        
        if deco.startswith('REGISTER'):
            self.lineaLog = " Received from "+str(self.client_address[0])+":"+str(self.client_address[1])+": "+deco
            self.imprimeLog()
            if deco.find('Authorization:')!=-1:
                self.ipUsuario = self.client_address[0]
                self.fechaReg = time.time()
                self.campoexpire = deco[deco.find('Expires:')+9:deco.find("\r\nAuth")]
                trozo = deco[deco.find('sip:')+4:deco.find('SIP')]
                self.puertoUsuario = trozo[trozo.find(':')+1:]
                self.direccion = trozo[:trozo.find(':')]
                self.dic[self.direccion] = self.client_address[0]
                self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                self.lineaLog = " Sent to "+str(self.client_address[0])+":"+str(self.client_address[1])+": "+"SIP/2.0 200 OK"
                self.imprimeLog()
                if self.campoexpire == '0\r\n':
                    del self.dic[self.direccion]
                self.register2json()
            else:
                cad = "SIP/2.0 401 Unauthorized\r\nWWW Authenticate: nonce=89898989"
                self.lineaLog = " Sent to "+str(self.client_address[0])+":"+str(self.client_address[1])+": "+cad
                self.imprimeLog()
                self.wfile.write(b"SIP/2.0 401 Unauthorized\r\nWWW Authenticate: nonce=89898989")
        elif deco.startswith('INVITE') or deco.startswith('BYE') or deco.startswith('ACK'):
            self.receptorUser = deco[deco.find(":")+1:deco.find("SIP")-1]
            self.lineaLog =  " Received from "+str(self.client_address[0])+":"+str(self.client_address[1])+": "+deco
            self.imprimeLog()
            for diccionario in self.listas:
                if diccionario['address'] == self.receptorUser and diccionario['expires'] >= time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time())):
                    self.contador += 1
                    direc = deco[deco.find('p:')+2:deco.find(' ')]
                    IPdestino = ""
                    # HAY QUE CAMBIAR ESTO
                    PUERTOdestino = 5000 
                    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    my_socket.connect((IPdestino, int(PUERTOdestino)))
                    print("Enviando: " + deco)
                    self.lineaLog =  " Sent to "+str(IPdestino)+":"+str(PUERTOdestino)+": "+deco
                    self.imprimeLog()
                    my_socket.send(bytes(deco, 'utf-8') + b'\r\n')
                    try:
                        data = my_socket.recv(1024)
                        r = data.decode('utf-8')
                        print('Recibido -- ', r)
                        self.lineaLog =  " Received from "+str(IPdestino)+":"+str(PUERTOdestino)+": "+r
                        self.imprimeLog()
                        if r.startswith("SIP/2.0 100") or r.startswith("SIP/2.0 200"):
                            self.lineaLog =  " Sent to "+str(self.client_address[0])+":"+str(self.client_address[1])+": "+r
                            self.imprimeLog()
                            self.wfile.write(data)
                    except:
                        self.wfile.write(b"Error: no server listening at that direction")
            if self.contador == 0:
                self.lineaLog =  " Sent to "+str(self.client_address[0])+":"+str(self.client_address[1])+": SIP/2.0 404 User Not Found\r\n"
                self.imprimeLog()
                self.contador = 0
                self.wfile.write(b"SIP/2.0 404 User Not Found\r\n")
        else:
            self.lineaLog =  " Sent to "+str(self.client_address[0])+":"+str(self.client_address[1])+": "+deco
            self.imprimeLog()
            self.wfile.write("SIP/2.0 405 Method Not Allowed")
                 

    def register2json(self):
        """ Gestionamos los usuarios registrados"""
        expira = time.strftime('%Y%m%d%H%M%S', time.gmtime(int(self.campoexpire)+time.time()))
        dicc2 = {'address':self.direccion,'ip':self.ipUsuario,'puerto':self.puertoUsuario,'fecha':self.fechaReg,'expires': expira,}
        # Recorremos la lista de listas de usuarios para que si ya existía el usuario, borremos su informacion
        # que será actualizada con su nuevo valor de expiración.
        for diccionario in self.listas:
            if diccionario['address'] == self.direccion:
                self.listas.remove(diccionario)
        self.listas.append(dicc2)
        # Comprobamos la expiracion de los usuarios registrados, y si alguno ha caducado lo borramos.
        for diccionario in self.listas:
            if diccionario['expires'] <= time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time())):
                self.listas.remove(dicc2)
        json.dump(self.listas, open(FICHEROREG,'w'), sort_keys=True, indent=4, separators=(',', ': '))

    def json2registered(self):
        """ Comprueba si existe un fichero json para usarlo como lista de usuarios registrados """
        try:
            self.listas = json.load(open(FICHEROREG,'r'))
        except:
            pass

    def imprimeLog(self):
        #hay que quitar saltos de linea de self.lineaLog
        #self.receptorUser = deco[deco.find(":")+1:deco.find("SIP")-1]
        #l = Template(self.lineaLog)
        #lineaSinSaltos = l.substitute(\r\n="\n")
        lineaSinSaltos = self.lineaLog.replace("\r\n"," ")
        log = open(FICHEROLOG,'a')
        log.write(time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))+lineaSinSaltos+"\r\n")
        log.close()

if __name__ == "__main__":
    # Creamos servidor de eco y escuchamos
    if len(sys.argv) != 2:
        sys.exit("Usage: python uaserver.py config")

    try:
        config = sys.argv[1]
        fich = etree.parse(str(config))
        raiz = fich.getroot()
        puertomio = raiz.find("server").attrib["puerto"]
        FICHEROLOG = raiz.find("log").attrib["path"]
        FICHEROREG = raiz.find("database").attrib["path"]
        serv = socketserver.UDPServer(('', int(puertomio)), SIPRegisterHandler)
        print("Server MiTesoro listening at port "+puertomio+"...")
        serv.serve_forever()
    except:
        sys.exit("Usage: python uaserver.py config")
