'''
Created on 9. 2. 2015

@author: vojta
'''
import sys
from scapy.all import rdpcap, Raw, TCP
import content_identifier as ci


class PcapParser():
    def __init__(self, pcapfile):
        self.pcapfile = pcapfile
        self.count = 0
        self.traffile = open("traffic.log", "w")
        self.ci = ci.ContentIdentifier()

    def writeRequest(self, request, num):
        self.traffile.write("Request #"+str(num)+"\n")
        ctype = self.getCtype(request)
        if self.ci.identifyContent(ctype, self.view, request.load) == True:
            self.traffile.write(request.load+"\n\n")
            reqfile = open("request"+str(num), 'w')
            reqfile.write(request.load)
            reqfile.close()
        else:
            self.traffile.write(request.load.split("\n\n")[0]+"\n\nSkipped data\n\n")

    def writeResponse(self, response, num):
        self.traffile.write("response #"+str(num)+"\n")
        ctype = self.getCtype(response)
        if self.ci.identifyContent(ctype, self.view, response.load) == True:
            self.traffile.write(response.load+"\n\n")
        else:
            self.traffile.write(response.load.split("\n\n")[0]+"\n\nSkipped data\n\n")

    def view(self, load):
        try:
            return load.decode()+"\n"
        except ValueError:
            decodedchars = ""
            for c in load:
                try:
                    c.decode()
                except ValueError:
                    continue
                decodedchars += c
            return decodedchars+"\n"



    def getCtype(self, p):
        substr = p.load.find("Content-Type") #let's find if it is regular HTTP request/response
        if substr != -1:
            ctype = p.load[substr+len("Content-Type: "):].split("\n")[0]
            if ctype.endswith("\r"):
                ctype = ctype[:-1]
        else:
            ctype = "None"
        return ctype

    def run(self):
        pl = rdpcap(self.pcapfile)
        for p in pl:
            if (TCP in p) and (Raw in p):
                if (p.sport in (80, 8080, 8000)) and (p.load.decode("utf-8", "replace")[:4] == "HTTP"):
                    p.load = p.load.replace("\r\n", "\n")
                    self.writeResponse(p, self.count)
                elif (p.dport in (80, 8080, 8000)) and (p.load.decode("utf-8", "replace")[:3].isalpha()):
                    p.load = p.load.replace("\r\n", "\n")
                    self.count += 1
                    self.writeRequest(p, self.count)
        self.ci.shutdown()

if __name__ == "__main__":
    p = PcapParser(sys.argv[1])
    p.run()