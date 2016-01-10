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
    

    def handle(self):
        """ Metodo principal del servidorproxy. """
        # Comprueba que no tenemos usuarios registrados, y llama al metodo json2registered.
        if self.listas == []:
            self.json2registered()
        # Escribe dirección y puerto del cliente (de tupla client_address)
        #print (self.client_address)
        line = self.rfile.read()
        print("El cliente nos manda " + line.decode('utf-8'))
        deco = line.decode('utf-8')
        
        if deco.startswith('REGISTER'):
            if deco.find('Authorization:')!=-1:
                self.ipUsuario = self.client_address[0]
                self.fechaReg = time.time()
                self.campoexpire = deco[deco.find('Expires:')+9:deco.find("\r\nAuth")]
                trozo = deco[deco.find('sip:')+4:deco.find('SIP')]
                self.puertoUsuario = trozo[trozo.find(':')+1:]
                self.direccion = trozo[:trozo.find(':')]
                self.dic[self.direccion] = self.client_address[0]
                self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                if self.campoexpire == '0\r\n':
                    del self.dic[self.direccion]
                #print(self.dic)
                self.register2json()
            else:
                self.wfile.write(b"SIP/2.0 401 Unauthorized\r\nWWW Authenticate: nonce=89898989")
        elif deco.startswith('INVITE') or deco.startswith('BYE') or deco.startswith('ACK'):
            direc = deco[deco.find('p:')+2:deco.find(' ')]
            IPdestino = ""
            PUERTOdestino = 5000 
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((IPdestino, int(PUERTOdestino)))
            print("Enviando: " + deco)
            my_socket.send(bytes(deco, 'utf-8') + b'\r\n')
            data = my_socket.recv(1024)
            r = data.decode('utf-8')
            print('Recibido -- ', r)
            if r.startswith("SIP/2.0 100") or r.startswith("SIP/2.0 200"):
                self.wfile.write(data)
        else:
            self.wfile.write("SIP/2.0 405 Method Not Allowed")

    def register2json(self):
        """ Gestionamos los usuarios registrados"""
        expira = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(self.campoexpire)+time.time()))
        dicc2 = {'address':self.direccion,'ip':self.ipUsuario,'puerto':self.puertoUsuario,'fecha':self.fechaReg,'expires': expira,}
        # Recorremos la lista de listas de usuarios para que si ya existía el usuario, borremos su informacion
        # que será actualizada con su nuevo valor de expiración.
        for diccionario in self.listas:
            if diccionario['address'] == self.direccion:
                self.listas.remove(diccionario)
        self.listas.append(dicc2)
        # Comprobamos la expiracion de los usuarios registrados, y si alguno ha caducado lo borramos.
        for diccionario in self.listas:
            if diccionario['expires'] <= time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time())):
                self.listas.remove(dicc2)
        json.dump(self.listas, open("registered.json",'w'), sort_keys=True, indent=4, separators=(',', ': '))

    def json2registered(self):
        """ Comprueba si existe un fichero json para usarlo como lista de usuarios registrados """
        try:
            self.listas = json.load(open("registered.json",'r'))
        except:
            pass

if __name__ == "__main__":
    # Creamos servidor de eco y escuchamos
    if len(sys.argv) != 2:
        sys.exit("Usage: python uaserver.py coooonfig")

    try:
        config = sys.argv[1]
        fich = etree.parse(str(config))
        raiz = fich.getroot()
        puertomio = raiz.find("server").attrib["puerto"]
        serv = socketserver.UDPServer(('', int(puertomio)), SIPRegisterHandler)
        print("Server MiTesoro listening at port "+puertomio+"...")
        serv.serve_forever()
    except:
        sys.exit("Usage: python uaserver.py config")
