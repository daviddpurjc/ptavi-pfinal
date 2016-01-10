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
    ipEmisor = ''
    puertoRTP = ''

    def handle(self):
        """ Metodo principal del servidor. """
        # Lee las lineas que manda el proxy, y actúa en consecuencia.
        line = self.rfile.read()
        print("El proxy nos manda " + line.decode('utf-8'))
        deco = line.decode('utf-8')
        # Envia la respuesta de Trying+Ring+OK, si recibe un INVITE.
        if deco.startswith('INVITE'):
            self.wfile.write(b"SIP/2.0 100 Trying\r\nSIP/2.0 180 Ring\r\nSIP/2.0 200 OK\r\n\r\n")
            origen = deco[deco.find('o='):deco.find('s=')]
            self.ipEmisor = origen[origen.find(' ')+1:]
            self.puertoRTP = deco[deco.find('audio')+6:deco.find('RTP')]
            print(origen+self.ipEmisor+self.puertoRTP)
        # Envia el audio al recibir el ACK.
        elif deco.startswith('ACK'):
            fichero_audio = raiz.find("audio").attrib["path"]
            print(self.ipEmisor)
            #Aqui tengo que hacer que lea ip y puerto de recepcion de rtp
            #origen = deco[deco.find('o='):deco.find('\r\n')]
            #ipEmisor = origen[origen.find(' ')+1:origen.find('\r\n')]
            #puertoRTP = deco[deco.find('audio')+6:deco.find(' ')]
            #print(origen)
            #print(ipEmisor)
            #print(puertoRTP)
            aEjecutar = "./mp32rtp -i "+self.ipEmisor+" -p "+self.puertoRTP+" < " + fichero_audio
            print("Vamos a ejecutar: ")
            print(aEjecutar)
            os.system(aEjecutar)
        # Cuando el servidor reciba el BYE significará el cese de la llamada.
        elif deco.startswith('BYE'):
            self.wfile.write(b"SIP/2.0 200 OK cuelga tu cuelgo yo")
        # Si el método no es válido, el servidor se lo hará saber.
        else:
            self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")

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
