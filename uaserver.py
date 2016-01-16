#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor de eco en UDP simple
"""

import socketserver
import os
import sys
import xml.etree.ElementTree as ET

class SIPHandler(socketserver.DatagramRequestHandler):
    """
    Echo server class
    """
    
    aEjecutar = ''
    origen = ''

    def handle(self):
        """ Metodo principal del servidor. """
        # Lee las lineas que manda el proxy, y actúa en consecuencia.
        
        line = self.rfile.read()
        print("El proxy nos manda " + line.decode('utf-8'))
        deco = line.decode('utf-8')

        # Envia la respuesta de Trying+Ring+OK, si recibe un INVITE.
        if deco.startswith('INVITE'):
            sdp1 = deco[deco.find("Content"):deco.find("audio")+6]
            sdp = sdp1+PRTP+" RTP"
            self.wfile.write(b"SIP/2.0 100 Trying\r\nSIP/2.0 180 Ring\r\nSIP\
/2.0 200 OK\r\n\r\n"+sdp.encode('utf-8'))
            self.origen = deco[deco.find('o=')+2:deco.find('s=')]
            ipEmisor = self.origen[self.origen.find(' \
')+1:self.origen.find("\r\n")]
            puertoRTP = deco[deco.find('audio')+6:deco.find('RTP')-1]
            fichero_audio = raiz.find("audio").attrib["path"]
            self.aEjecutar = "./mp32rtp -i "+ipEmisor+" \
-p "+puertoRTP+" < " + fichero_audio
            self.guarda()
        # Envia el audio al recibir el ACK.
        elif deco.startswith('ACK'):
            logo = open("linea.txt",'r')
            linea = logo.readline()
            envio = linea[:linea.find(",")]
            d = linea[linea.find(",")+1:]
            di = d[:d.find(" ")]
            print("Vamos a ejecutar: ")
            print(envio)
            os.system(envio)
            #os.system("cvlc rtp://@"+IP+":"+PRTP)
            #self.wfile.write(b"BYE sip:\
#"+di.encode('utf-8')+b" SIP/2.0\r\n")
        # Cuando el servidor reciba el BYE significará el cese de la llamada.
        elif deco.startswith('BYE'):
            self.wfile.write(b"SIP/2.0 200 OK")
        # Si el método no es válido, el servidor se lo hará saber.
        else:
            self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")

    def guarda(self):
        logg = open("linea.txt",'w')
        logg.write(self.aEjecutar+","+self.origen)
        logg.close()

if __name__ == "__main__":
    # Creamos servidor de eco y escuchamos

    if len(sys.argv) != 2:
        sys.exit("Usage: python uaserver.py config")

    try:
        config = sys.argv[1]
        fich = ET.parse(str(config))
        raiz = fich.getroot()
        puertomine = raiz.find("uaserver").attrib["puerto"]
        PRTP = raiz.find("rtpaudio").attrib["puerto"]
        ip = raiz.find("uaserver").attrib["ip"]
        if ip == "":
            IP = "127.0.0.1"
        else:
            IP = ip
        serv = socketserver.UDPServer(('', int(puertomine)), SIPHandler)
        print("Listening...")
        serv.serve_forever()
    except:
        sys.exit("Usage: python uaserver.py config")
