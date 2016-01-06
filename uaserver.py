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

    def handle(self):
        """ Metodo principal del servidor. """
        # Lee las lineas que manda el cliente, y actúa en consecuencia.
        line = self.rfile.read()
        print("El cliente nos manda " + line.decode('utf-8'))
        deco = line.decode('utf-8')
        # Envia la respuesta de Trying+Ring+OK, si recibe un INVITE.
        if deco.startswith('INVITE'):
            self.wfile.write(b"SIP/2.0 100 Trying\r\n")
            self.wfile.write(b"SIP/2.0 180 Ring\r\nSIP/2.0 200 OK\r\n\r\n")
        # Envia el audio al recibir el ACK.
        elif deco.startswith('ACK'):
            fichero_audio = str(sys.argv[3])
            aEjecutar = "./mp32rtp -i 127.0.0.1 -p 23032 < " + fichero_audio
            print("Vamos a ejecutar: ")
            print(aEjecutar)
            os.system(aEjecutar)
        # Cuando el servidor reciba el BYE significará el cese de la llamada.
        elif deco.startswith('BYE'):
            self.wfile.write(b"Cuelga tu, cuelgo yo")
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
        PUERTO = raiz.find("uaserver").attrib["puerto"]
        serv = socketserver.UDPServer(('', PUERTO), SIPHandler)
        print("Listening...")
        serv.serve_forever()
    except:
        sys.exit("Usage: python uaserver.py config")
