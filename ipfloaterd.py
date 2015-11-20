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
        return "%s%s\n%s\n%s\n%s\n%s\n%s\n%s" % (head, rule1, rule1b, rule2, rule2b, rule3, rule3b, bottom)

    def __str__(self, ):
        return "%s:%d -> %s:%d" % (self.public_ip, self.public_port, self.private_ip, self.private_port)
    

class EndpointManager():
    def __init__(self, db_string):
        self._public2private = {}
        self._private2public = {}
    
    def __str__(self):
        retval = ""
        for ip in self._public2private:
            for _, ep in self._public2private[ip].items():
                retval = "%s%s\n" % (retval, ep)
        return retval
    
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
    
            if len(ip_list) == 0:
                _LOGGER.warning("requested a redirection for %s:%d but we have not free public ips" % (private_ip, private_port))
                return None
            
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
    
    def _remove_ep(self, endpoint):
        if endpoint is None:
            return False
        
        if endpoint.private_ip not in self._private2public: return False
        if endpoint.private_port not in self._private2public[endpoint.private_ip]: return False
        if endpoint.public_ip not in self._public2private: return False
        if endpoint.public_port not in self._public2private[endpoint.public_ip]: return False
        
        del (self._public2private[endpoint.public_ip])[endpoint.public_port]
        del (self._private2public[endpoint.private_ip])[endpoint.private_port]
        if len(self._private2public[endpoint.private_ip]) == 0:
            del self._private2public[endpoint.private_ip]
            
        return True

    def _get_ep_from_private(self, private_ip, private_port):
        if private_ip not in self._private2public:
            return None
        
        if private_port not in self._private2public[private_ip]:
            return None
        
        return (self._private2public[private_ip])[private_port]

    def _get_ep_from_public(self, public_ip, public_port):
        if public_ip not in self._public2private:
            return None
        
        if public_port not in self._public2private[public_ip]:
            return None
        
        return (self._public2private[public_ip])[public_port]
    
    def _check_availability(self, ep_list, ip, port, consider_available_if_ip_not_exists = True):
        if ip in ep_list:
            if 0 in ep_list[ip]: return False
            if port in ep_list[ip]: return False
        else:
            if consider_available_if_ip_not_exists:
                return True
            else:
                return False
        return True
    
    def _public_available(self, public_ip, public_port):
        return self._check_availability(self._public2private, public_ip, public_port, False)

    def _private_available(self, private_ip, private_port):
        return self._check_availability(self._private2public, private_ip, private_port, True)

    def _remove_eps_from_list(self, ep_list):
        ep_list = [ ep for _,ep in ep_list.items() ]
        error = False
        for ep in ep_list:
            if not self._remove_ep(ep):
                error = True
                _LOGGER.error("failed to remove endpoint: %s" % ep)
        return (not error)
    
    def _get_ep(self, ep):
        return self._get_ep_from_private(ep.private_ip, ep.private_port)    
    
    def apply_endpoint(self, ep):
        '''
        This function applies an endpoint (if it is possible)
        '''
        
        if not self._private_available(ep.private_ip, ep.private_port):
            _LOGGER.warning("tried to apply a redirection to %s:%d but it is already occupied" % (ep.private_ip, ep.private_port))
            return False            

        if not self._public_available(ep.public_ip, ep.public_port):
            _LOGGER.warning("tried to apply a redirection from %s:%d but it is either occupied or the ip is not managed by ipfloater" % (ep.public_ip, ep.public_port))
            return False
        
        # TODO: apply on iptables
        self._add_ep(ep)
        return True        
    
    def request_endpoint(self, private_ip, private_port, public_port = -1):
        if not self._private_available(private_ip, private_port):
            _LOGGER.warning("requesting a redirection to %s:%d, but it is already occupied" % (private_ip, private_port))
            return None
        
        ep = self._select_public_ip(private_ip, private_port, public_port)
        return ep
        
    def terminate_redirection(self, private_ip, private_port):
        ep = self._get_ep_from_private(private_ip, private_port)
        if ep is None:
            return False
        
        return self._remove_ep(ep)

    def free_endpoint(self, ep):
        if self._get_ep(ep) is None:
            _LOGGER.warning("tried to remove and endpoint that does not exist %s" % ep)
            return False
        _LOGGER.debug("endpoint %s successfully removed" % ep)
        return True
    
    def clean_private_ip(self, private_ip):
        if private_ip not in self._private2public:
            return True
        return self._remove_eps_from_list(self._private2public[private_ip])
    
    def clean_public_ip(self, public_ip):
        if public_ip not in self._public2private:
            return False
        return self._remove_eps_from_list(self._public2private[public_ip])
    
_ENDPOINT_MANAGER = None

def query_endpoint(dst_ip, dst_port, register = True):
    '''
    '''
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"
    
    ep = _ENDPOINT_MANAGER.request_endpoint(dst_ip, dst_port)
    if ep is None:
        return False, "Could not obtain a redirection for %s:%d" % (dst_ip, dst_port)
    
    if register:
        if not _ENDPOINT_MANAGER.apply_endpoint(ep):
            return False, "Could not apply the redirection %s" % ep

    return True, ep

def unregister_endpoint(dst_ip, dst_port):
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    ep = _ENDPOINT_MANAGER.terminate_redirection(dst_ip, dst_port)
    if ep is None:
        return False, "Could not delete the redirection to %s:%d. Does it exist?" % (dst_ip, dst_port)
    
    return True, "Redirection %s unregistered" % ep

def clean_private_ip(private_ip):
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    if not _ENDPOINT_MANAGER.clean_private_ip(private_ip):
        return False, "Could not clean the redirections to %s. Do they exist?" % (private_ip)
    
    return True, "Redirections to %s unregistered" % private_ip

def clean_public_ip(public_ip):
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    if not _ENDPOINT_MANAGER.clean_public_ip(public_ip):
        return False, "Could not clean the redirections from %s. Do they exist?" % (public_ip)
    
    return True, "Redirections from %s unregistered" % public_ip

if __name__ == '__main__':
    #logging.basicConfig(filename=None,level=logging.DEBUG)
    #epm = EndpointManager("")
    #epm.add_public_ip("10.0.0.72")
    #epm.add_public_ip("10.0.0.69")
    #
    #ep = epm.request_endpoint("10.3.0.5", 0)
    #print ep.ipt()
    #epm.apply_endpoint(ep)
    #print epm
    #
    #ep = epm.request_endpoint("10.3.0.7", 0)
    #print ep.ipt()
    #epm.apply_endpoint(ep)
    #print epm
    #
    #ep = epm.request_endpoint("10.3.0.8", 22)
    #print ep.ipt()
    #epm.apply_endpoint(ep)
    #print epm
    #
    #
    #epm.clean_private_ip("10.3.0.7")
    #print epm
    #
    ##print (epm.query_endpoint("192.168.1.1", 0)).ipt()
    ##print (epm.query_endpoint("192.168.1.2", 1)).ipt()
    ##print epm.query_endpoint("192.168.1.3", 1)
    ##print epm.query_endpoint("192.168.1.2", 3)
    ##print epm.query_endpoint("192.168.1.2", 4)
    ##print epm.query_endpoint("192.168.1.2", 5)
    ##print epm.query_endpoint("192.168.1.2", 6)
    ### print epm.query_endpoint("192.168.1.1", 3)
    ##print epm.query_endpoint("192.168.1.3", 3)
    #sys.exit(0)


# if __name__ == '__main__':
    logging.basicConfig(filename=None,level=logging.DEBUG)
    eventloop.create_eventloop(True)
    
    ap = CmdLineParser("ipfloater", "This is a server that deals with iptables to enable floating IPs in private networks", [
        Parameter("--db-file", "-d", "The path for the persistence file", 1, False, "ipfloater.db"),
        Parameter("--listen-ip", "-i", "The ip adress in which ipfloater will listen", 1, False, ["127.0.0.1"]),
        Parameter("--listen-port", "-p", "The ip port in which ipfloater will listen", 1, False, [7000]),
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

    SERVER=result.values['--listen-ip'][0]
    PORT=result.values['--listen-port'][0]

    _ENDPOINT_MANAGER = EndpointManager("")
    if not xmlrpcutils.create_xmlrpc_server_in_thread(SERVER, PORT, [query_endpoint, unregister_endpoint, clean_private_ip, clean_public_ip]):
        _LOGGER.error("could not setup the service")
        raise Exception("could not setup the service")

    _LOGGER.info("server running in %s:%d" % (SERVER, PORT))

    #global _DATABASE
    #_DATABASE = db.DB.create_from_string("sqlite://./floatip.db")
    #if _DATABASE is None:
    #    raise Exception("could not connect to the database")
    #
    #_LOGGER.debug("connecting to the database")    
    #_DATABASE.connect()
    
    eventloop.get_eventloop().loop()
