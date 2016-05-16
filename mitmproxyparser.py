'''
Created on 31. 10. 2014

@author: vojta
'''

from mitmproxy import proxy, dump, protocol
from mitmproxy.proxy.server import ProxyServer
import os, sys, getopt
import content_identifier as ci


class RequestProcessor(dump.DumpMaster):
    def __init__(self, server, options):
        self.reqcount = 0
        self.respcount = 0
        self.traffic = open("traffic.log", "w")
        self.ci = ci.ContentIdentifier()
        dump.DumpMaster.__init__(self, server, options)

    def shutdown(self):
        self.traffic.close()
        self.ci.shutdown()
        dump.DumpMaster.shutdown(self)

    def run(self):
        try:
            return dump.DumpMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, flow):
        fd = open("request"+str(self.reqcount), 'w')
        result = flow.request.method+" "+flow.request.path+" HTTP/1.1\n"
        for header in flow.request.headers.iteritems():
            result += header[0]+": "+header[1]+"\n"
        if (flow.request.method == "POST") and (flow.request.content):
            if self.ci.identifyContent(flow.request.headers["Content-Type"], self.view, flow.request) == True:
                result += "\n"+flow.request.content+"\n"
            else:
                result += "\nContent skipped\n"
        fd.write(result)
        fd.close()
        result = "Request #"+str(self.reqcount)+":\n"+result+"\n"
        self.traffic.write(result)
        #print (result)
        self.reqcount += 1
        flow.reply()

    def handle_response(self, flow):
        result = "Response #"+str(self.respcount)+":\n"
        result += str(flow.response.status_code)+": "+flow.response.reason
        for header in flow.response.headers.iteritems():
            result += header[0]+": "+header[1]+"\n"
        if flow.response.content:
            if (flow.response.headers["Content-Type"] != None) and (self.ci.identifyContent(flow.response.headers["Content-Type"], self.view, flow.response) == True):
                result += flow.response.content
            else:
                result += "\nContent skipped"
        result += "\n"
        self.traffic.write(result)
        #print (result)
        self.respcount += 1
        flow.reply()

    def view(self, msg):
        try:
            return msg.content.decode()+"\n"
        except ValueError:
            decodedchars = ""
            for c in msg.content:
                try:
                    c.decode()
                except ValueError:
                    continue
                decodedchars += c
            return decodedchars+"\n"



def main():
    opts, args = getopt.getopt(sys.argv[1:], 'r:o:l')
    for o, a in opts:
        if o == '-r':
            inFile = os.path.abspath(a)
            m = RequestProcessor(server=None, options = dump.Options(rfile=inFile))
            m.run()
        elif o == '-l':
            config = proxy.ProxyConfig(port=8321)
            server = ProxyServer(config)
            m = RequestProcessor(server, dump.Options())
            m.run()

main()