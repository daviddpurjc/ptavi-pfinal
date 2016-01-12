#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor de eco en UDP simple
"""

import socketserver
import os
import sys
from lxml import etree

class SIPHandler(socketserver.DatagramRequestHandler):
    """
    Echo server class
    """
    #ipEmisor = ''
    #puertoRTP = ''
    aEjecutar = ''
    #linea = ''

    def handle(self):
        """ Metodo principal del servidor. """
        # Lee las lineas que manda el proxy, y actúa en consecuencia.
        line = self.rfile.read()
        print("El proxy nos manda " + line.decode('utf-8'))
        deco = line.decode('utf-8')
        # Envia la respuesta de Trying+Ring+OK, si recibe un INVITE.
        if deco.startswith('INVITE'):
            sdp = deco[deco.find("Content"):]
            self.wfile.write(b"SIP/2.0 100 Trying\r\nSIP/2.0 180 Ring\r\nSIP/2.0 200 OK\r\n\r\n"+sdp.encode('utf-8'))
            origen = deco[deco.find('o='):deco.find('s=')]
            ipEmisor = origen[origen.find(' ')+1:origen.find("\r\n")]
            puertoRTP = deco[deco.find('audio')+6:deco.find('RTP')-1]
            fichero_audio = raiz.find("audio").attrib["path"]
            self.aEjecutar = "./mp32rtp -i "+ipEmisor+" -p "+puertoRTP+" < " + fichero_audio
            print(self.aEjecutar)
            self.guarda()
        # Envia el audio al recibir el ACK.
        elif deco.startswith('ACK'):
            logo = open("linea.txt",'r')
            print("Vamos a ejecutar: ")
            print(logo.readline())
            os.system(logo.readline())
            self.wfile.write(b"BYE sip: papapapapa SIP/2.0\r\n")
        # Cuando el servidor reciba el BYE significará el cese de la llamada.
        elif deco.startswith('BYE'):
            self.wfile.write(b"SIP/2.0 200 OK cuelga tu cuelgo yo")
        # Si el método no es válido, el servidor se lo hará saber.
        else:
            self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")

    def guarda(self):
        logg = open("linea.txt",'a')
        logg.write(self.aEjecutar)
        logg.close()

if __name__ == "__main__":
    # Creamos servidor de eco y escuchamos

    if len(sys.argv) != 2:
        sys.exit("Usage: python uaserver.py config")

    try:
        config = sys.argv[1]
        fich = etree.parse(str(config))
        raiz = fich.getroot()
        puertomine = raiz.find("uaserver").attrib["puerto"]
        serv = socketserver.UDPServer(('', int(puertomine)), SIPHandler)
        print("Listening...")
        serv.serve_forever()
    except:
        sys.exit("Usage: python uaserver.py config")
