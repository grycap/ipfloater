import sys
from cpyutils.parameters import CmdLineParser, Flag, Parameter, Argument, Operation
import cpyutils.eventloop as eventloop
import cpyutils.db as db
import cpyutils.xmlrpcutils as xmlrpcutils
import logging

if __name__ == '__main__':
    logging.basicConfig(filename=None,level=logging.DEBUG)
    eventloop.create_eventloop(True)

    class IPFloaterCmdLine(CmdLineParser):
        def preops(self, result, error):
            SERVER=result.values['--listen-ip'][0]
            PORT=result.values['--listen-port'][0]
            self._XMLRPC_SERVER = xmlrpcutils.ServerProxy("http://%s:%d" % (SERVER, PORT))

        def getip(self, result, error):
            return True, "success"
        
        def releaseip(self, result, error):
            print "releaseip"
            return True, "success"
    
    ap = IPFloaterCmdLine("ipfloater", "This the client for ipfloaterd, which is a server that deals with iptables to enable floating IPs in private networks", [
        Parameter("--listen-ip", "-i", "The ip adress in which ipfloater listens", 1, False, ["127.0.0.1"]),
        Parameter("--listen-port", "-p", "The ip port in which ipfloater listens", 1, False, [7000]),
            Operation("getip", desc = "Requests a floating IP for a private IP", arguments = [
                Argument("ip", "private ip address to which is requested the floating ip", mandatory = True, count = 1),
            ]),
            Operation("releaseip", desc = "Releases the floating IP to a private IP", arguments = [
                Argument("ip", "private ip address to which is granted the floating ip", mandatory = True, count = 1),
            ]),
    ])


    ap.self_service(True)

    #parsed, result, info = ap.parse(sys.argv[1:])
    #if not parsed:
    #    if (result is None):
    #        print "Error:", info
    #        sys.exit(-1)
    #    else:
    #        print info
    #        sys.exit(0)
