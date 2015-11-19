import sys
from cpyutils.parameters import CmdLineParser, Flag, Parameter, Argument
import cpyutils.eventloop as eventloop
import cpyutils.db as db
import cpyutils.xmlrpcutils as xmlrpcutils
import logging
import random


'''
-P PREROUTING ACCEPT
-P POSTROUTING ACCEPT
-P OUTPUT ACCEPT
-N quantum-l3-agent-OUTPUT
-N quantum-l3-agent-POSTROUTING
-N quantum-l3-agent-PREROUTING
-N quantum-l3-agent-float-snat
-N quantum-l3-agent-snat
-N quantum-postrouting-bottom
-A PREROUTING -j quantum-l3-agent-PREROUTING 
-A POSTROUTING -j quantum-l3-agent-POSTROUTING 
-A POSTROUTING -j quantum-postrouting-bottom 
-A OUTPUT -j quantum-l3-agent-OUTPUT 
-A quantum-l3-agent-OUTPUT -d 172.24.4.228/32 -j DNAT --to-destination 10.1.0.2 
-A quantum-l3-agent-POSTROUTING ! -i qg-d48b49e0-aa ! -o qg-d48b49e0-aa -m conntrack ! --ctstate DNAT -j ACCEPT 
-A quantum-l3-agent-PREROUTING -d 169.254.169.254/32 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 9697 
-A quantum-l3-agent-PREROUTING -d 172.24.4.228/32 -j DNAT --to-destination 10.1.0.2 
-A quantum-l3-agent-float-snat -s 10.1.0.2/32 -j SNAT --to-source 172.24.4.228 
-A quantum-l3-agent-snat -j quantum-l3-agent-float-snat 
-A quantum-l3-agent-snat -s 10.1.0.0/24 -j SNAT --to-source 172.24.4.227 
-A quantum-postrouting-bottom -j quantum-l3-agent-snat 


-A quantum-l3-agent-OUTPUT -d 172.24.4.228/32 -j DNAT --to-destination 10.1.0.2 
-A quantum-l3-agent-PREROUTING -d 172.24.4.228/32 -j DNAT --to-destination 10.1.0.2 
-A quantum-l3-agent-float-snat -s 10.1.0.2/32 -j SNAT --to-source 172.24.4.228 
'''


_LOGGER = logging.getLogger("[IPFLOATER]")
SERVER="127.0.0.1"
PORT=7000

_id = -1
class Endpoint(object):
    @staticmethod
    def get_id():
        global _id
        _id = _id + 1
        return _id
    
    def __init__(self, public_ip, public_port, private_ip, private_port):
        self.id = Endpoint.get_id()
        self.public_ip = public_ip
        self.public_port = public_port
        self.private_ip = private_ip
        self.private_port = private_port

    def iptables_apply(self):
        return False
    
    def iptables_remove(self):
        return False

    def ipt(self, new = False):
        head = "\
iptables -t nat -N rule-%d-OUTPUT\n\
iptables -t nat -N rule-%d-PREROUTING\n\
iptables -t nat -N rule-%d-POSTROUTING\n\
iptables -t nat -A OUTPUT -j rule-%d-OUTPUT\n\
iptables -t nat -A PREROUTING -j rule-%d-PREROUTING\n\
iptables -t nat -A POSTROUTING -j rule-%d-POSTROUTING\n\
" % (self.id, self.id, self.id, self.id, self.id, self.id)
        bottom = "\
iptables -t nat -D OUTPUT -j rule-%d-OUTPUT\n\
iptables -t nat -D PREROUTING -j rule-%d-PREROUTING\n\
iptables -t nat -D POSTROUTING -j rule-%d-POSTROUTING\n\
iptables -t nat -X rule-%d-OUTPUT\n\
iptables -t nat -X rule-%d-PREROUTING\n\
iptables -t nat -X rule-%d-POSTROUTING\
" % (self.id, self.id, self.id, self.id, self.id, self.id)
        if new:
            action = "-A"
            bottom = ""
        else:
            action = "-D"
            head = ""
            
        # solucion de nat loopback: en postrouting, si el source es la LAN y el destino es     
        # iptables -t nat -A rule-0-POSTROUTING -s 10.3.0.5/24 -d 10.3.0.5/32 -p tcp --dport 22 -j SNAT --to-source 10.0.0.69
        
        if (self.public_port == 0) and (self.private_port == 0):
            # regla desde dentro, hacia dentro (para que no salga fuera de la red)
            rule1 = "iptables -t nat %s rule-%d-OUTPUT -d %s/32 -j DNAT --to-destination %s" % (action, self.id, self.public_ip, self.private_ip)
            rule1b = "iptables -t nat %s rule-%d-OUTPUT -j RETURN" % (action, self.id)
            
            # regla de si me viene desde fuera y el destino es la ip publica y el puerto indicado, que me haga DNAT cambiando el destino a la IP privada y el puerto redirigido
            rule2 = "iptables -t nat %s rule-%d-PREROUTING -d %s/32 -j DNAT --to-destination %s" % (action, self.id, self.public_ip, self.private_ip)
            rule2b = "iptables -t nat %s rule-%d-PREROUTING -j RETURN" % (action, self.id)
            
            rule3 = "iptables -t nat %s rule-%d-POSTROUTING -s %s/32 -j SNAT --to-source %s" % (action, self.id, self.private_ip, self.public_ip)
            rule3b = "iptables -t nat %s rule-%d-POSTROUTING -j RETURN" % (action, self.id)
        else:
            # regla desde dentro, hacia dentro (para que no salga fuera de la red)
            rule1 = "iptables -t nat %s rule-%d-OUTPUT -d %s/32 -p tcp --dport %d -j DNAT --to-destination %s:%d" % (action, self.id, self.public_ip, self.public_port, self.private_ip, self.private_port)
            rule1b = "iptables -t nat %s rule-%d-OUTPUT -j RETURN" % (action, self.id)
            
            # regla de si me viene desde fuera y el destino es la ip publica y el puerto indicado, que me haga DNAT cambiando el destino a la IP privada y el puerto redirigido
            rule2 = "iptables -t nat %s rule-%d-PREROUTING -d %s/32 -p tcp --dport %d -j DNAT --to-destination %s:%d" % (action, self.id, self.public_ip, self.public_port, self.private_ip, self.private_port)
            rule2b = "iptables -t nat %s rule-%d-PREROUTING -j RETURN" % (action, self.id)
            
            rule3 = "iptables -t nat %s rule-%d-POSTROUTING -s %s/32 -p tcp --sport %d -j SNAT --to-source %s:%d" % (action, self.id, self.private_ip, self.public_port, self.public_ip, self.public_port)
            rule3b = "iptables -t nat %s rule-%d-POSTROUTING -j RETURN" % (action, self.id)
        return "%s%s\n%s\n%s\n%s\n%s\n%s%s" % (head, rule1, rule1b, rule2, rule2b, rule3, rule3b, bottom)

    def __str__(self, ):
        return "%s:%d -> %s:%d" % (self.public_ip, self.public_port, self.private_ip, self.private_port)
    

class EndpointManager():
    def __init__(self, db_string):
        self._public2private = {}
        self._private2public = {}
    
    def add_public_ip(self, ip):
        if ip in self._public2private:
            return True

        self._public2private[ip] = {}
        
    def _select_public_ip(self, private_ip, private_port, public_port):
        if public_port < 0:
            public_port = private_port
        
        if ((public_port == 0) and (private_port != 0)) or ((private_port == 0) and (public_port != 0)):
            _LOGGER.error("Requested one port to all endpoint. It is only possible to forward one-to-one or all-to-all")
            return None
        
        selected_ip = None
        if private_port == 0:
            # Let's check whether the internal IP is also redirected
            if private_ip in self._private2public:
                if 0 not in self._private2public[private_ip]:
                    # TODO: include an option to consider ip forwarding even if there are existing rules: i.e. clean the existing rules
                    _LOGGER.error("The IP %s has some ports redirected" % private_ip)
                    return None
                else:
                    ep = self._private2public[private_ip][0]
                    selected_ip = ep.public_ip
            else:
                # let's look for a free IP
                free_ips = [ ip for ip in self._public2private if len(self._public2private[ip]) == 0 ]
                if len(free_ips) == 0:
                    # could not find a free IP
                    _LOGGER.debug("could not find a free public IP")
                    return None
                else:
                    # TODO: implement different policies: random, prioritized, round robbin, etc.
                    selected_ip = free_ips[random.randint(0, len(free_ips) - 1)]
        else:
            
            public_ips = {}
            if private_ip in self._private2public:
                if 0 in self._private2public[private_ip]:
                    ep = (self._private2public[private_ip])[0]
                    _LOGGER.warning("requested a public ip for %s:%d while the whole ip is redirected from %s" % (private_ip, private_port, ep.public_ip))
                    return None

                for port, ep in self._private2public[private_ip].items():
                    if ep.public_ip not in public_ips:
                        public_ips[ep.public_ip] = 0
                    public_ips[ep.public_ip] += 1
    
                ip_list = [ (ip, public_ips[ip]) for ip in public_ips ]
            else:
                ip_list = []
    
            if len(ip_list) == 0:
                # The private IP has not been redirected, yet... let's find an IP that does not has the port redirected
                for ip in self._public2private:
                    if 0 not in self._public2private[ip]:
                        if public_port not in self._public2private[ip]:
                            ip_list.append((ip, -len(self._public2private[ip])))
    
            ip_sorted = sorted(ip_list, key = lambda ip : ip[1])
            (selected_ip, _) = ip_sorted[0]
        
        return Endpoint(selected_ip, public_port, private_ip, private_port)
    
    def _add_ep(self, endpoint):
        if endpoint is None:
            return False
        
        if endpoint.public_ip not in self._public2private:
            _LOGGER.error("tried to redirect a public ip that it is not managed by us")
            return False
        
        if endpoint.private_ip not in self._private2public:
            self._private2public[endpoint.private_ip] = {}
            
        self._private2public[endpoint.private_ip][endpoint.private_port] = endpoint
        self._public2private[endpoint.public_ip][endpoint.public_port] = endpoint
        
        return True
    
    def _add_redirection(self, private_ip, private_port, public_ip, public_port):
        ep = Endpoint(public_ip, public_port, private_ip, private_port)
        return self._add_ep(ep)
    
    def request_endpoint(self, private_ip, private_port, public_port = -1):
        ep = self._select_public_ip(private_ip, private_port, public_port)
        return ep

    def apply_endpoint(self, ep):
        # Will check if it is possible to apply (i.e. the ips and ports are available)
        occupied = False
        if ep.private_ip in self._private2public:
            if ep.private_port in self._private2public[ep.private_ip]:
                _LOGGER.warning("tried to apply a redirection to %s:%d but it is already occupied" % (ep.private_ip, ep.private_port))
                return False
        if ep.public_ip not in self._public2private:
            _LOGGER.warning("tried to apply a redirection from an unkonwn public ip: %s" % ep.public_ip)
            return False
        
        if ep.public_port in self._public2private[ep.public_ip]:
            _LOGGER.warning("tried to apply a redirection from %s:%d but it is already occupied" % (ep.public_ip, ep.public_port))
            return False

        # TODO: apply on iptables
        
        self._add_ep(ep)
        return True        
    
    def terminate_endpoint(self, private_ip, private_port):
        pass
    
    def terminate_endpoints(self, private_ip):
        pass
    

def query_endpoint(dst_ip, dst_port, register = True):
    '''
    '''
    pass


def register_endpoint(src_ip, src_port, dst_ip, dst_port):
    pass

def unregister_endpoint(src_ip, src_port, dst_ip, dst_port):
    pass

def unregister_by_id(endpoint_id):
    pass

if __name__ == '__main__':
    logging.basicConfig(filename=None,level=logging.DEBUG)
    epm = EndpointManager("")
    epm.add_public_ip("10.0.0.72")
    epm.add_public_ip("10.0.0.69")

    print (epm.request_endpoint("10.3.0.5", 22)).ipt()
    print (epm.request_endpoint("10.3.0.7", 0)).ipt()
    
    #print (epm.query_endpoint("192.168.1.1", 0)).ipt()
    #print (epm.query_endpoint("192.168.1.2", 1)).ipt()
    #print epm.query_endpoint("192.168.1.3", 1)
    #print epm.query_endpoint("192.168.1.2", 3)
    #print epm.query_endpoint("192.168.1.2", 4)
    #print epm.query_endpoint("192.168.1.2", 5)
    #print epm.query_endpoint("192.168.1.2", 6)
    ## print epm.query_endpoint("192.168.1.1", 3)
    #print epm.query_endpoint("192.168.1.3", 3)
    sys.exit(0)


# if __name__ == '__main__':
    logging.basicConfig(filename=None,level=logging.DEBUG)
    eventloop.create_eventloop(True)
    
    ap = CmdLineParser("ipfloater", "This is a server that deals with iptables to enable floating IPs in private networks", [
        Parameter("--public-interface", "-p", "The public network interface (default: eth0)", 1, False, "eth0"),
        Parameter("--private-interface", "-i", "The internal network interface (default: eth1)", 1, False, "eth1"),
    ])

    parsed, result, info = ap.parse(sys.argv[1:])
    # print result.values
    if not parsed:
        if (result is None):
            print "Error:", info
            sys.exit(-1)
        else:
            print info
            sys.exit(0)
    else:
        print info

        
    if not xmlrpcutils.create_xmlrpc_server_in_thread(SERVER, PORT, [register_endpoint, unregister_by_id, unregister_endpoint]):
        _LOGGER.error("could not setup the service")
        raise Exception("could not setup the service")

    _LOGGER.info("server running in %s:%d" % (SERVER, PORT))

    global _DATABASE
    _DATABASE = db.DB.create_from_string("sqlite://./floatip.db")
    if _DATABASE is None:
        raise Exception("could not connect to the database")

    _LOGGER.debug("connecting to the database")    
    _DATABASE.connect()
    
    eventloop.get_eventloop().loop()
