import sys
import version
from cpyutils.parameters import CmdLineParser, Flag, Parameter, Argument
import cpyutils.eventloop as eventloop
import cpyutils.db as db
import cpyutils.xmlrpcutils as xmlrpcutils
import logging
import random
import iptc
import uuid

'''
In the awful case that a uuid already exists in the iptables table, how should the endpoint proceed? The
  OVERWRITE_RULES flag states wether to overwrite the rule or raise an error.
  - perhaps a new id should be generated? (this could happen although statiscally has a low probability)
  - this flag in inherited from when sequential numbers were used for ids and all started at 0 at boot
'''
OVERWRITE_RULES=True

_LOGGER = logging.getLogger("[IPFLOATER]")

def string_and_log(txt, loglevel = logging.DEBUG):
    if loglevel == logging.DEBUG:
        _LOGGER.debug(txt)
    elif loglevel == logging.INFO:
        _LOGGER.info(txt)
    elif loglevel == logging.WARNING:
        _LOGGER.info(txt)
    elif loglevel == logging.ERROR:
        _LOGGER.error(txt)
    else:
        _LOGGER.debug(txt)
    return txt

def _ipt_delete_chain(table, chain_name):
    '''
    This function removes the iptables chain with name "chain_name" from the table object addressed by "table".
    If the chain is not in the table, this function does nothing.
    '''
    chains = [ chain.name for chain in table.chains if chain.name == chain_name ]
    if len(chains) > 0:
        chain = iptc.Chain(table, chain_name)
        for rule in chain.rules[:]:
            chain.delete_rule(rule)
        chain.delete()

def _ipt_link_chains(table, first_chain, second_chain):
    '''
    This function executes an iptables rule that links the chain named "first_chain" to the chain named "second_chain"
    in table "table". At the end, it creates a rule like: iptables -t table.name -A FIRST_CHAIN -j SECOND_CHAIN
    '''
    rule = iptc.Rule()
    rule.target = rule.create_target(second_chain)
    chain = iptc.Chain(table, first_chain)
    chain.insert_rule(rule)
    
def _ipt_unlink_chains(table, first_chain, second_chain):
    '''
    This function executes an iptables rule that unlinks the chain named "first_chain" to the chain named "second_chain"
    in table "table". At the end, it creates a rule like: iptables -t table.name -D FIRST_CHAIN -j SECOND_CHAIN
    '''
    chains = [ chain.name for chain in table.chains if chain.name == first_chain ]
    if len(chains) > 0:
        chain = iptc.Chain(table, first_chain)
        rules = [ rule for rule in chain.rules if rule.target.standard_target == second_chain ]
        for rule in rules:
            chain.delete_rule(rule)

def _ipt_chain_exists(table, chain_name):
    '''
    This function returns true if the iptables chain named "chain_name" is in table "table"
    '''
    chains = [ chain.name for chain in table.chains if chain.name == chain_name ]
    if len(chains) > 0:
        return True
    else:
        return False

def _ipt_remove_endpointchains(idendpoint):
    '''
    This method executes the needed funtions to remove the set of iptables rules that will make possible a redirection with the id in idendpoint.
    '''
    table = iptc.Table(iptc.Table.NAT)
    table.refresh()
    table.autocommit = False
    _ipt_unlink_chains(table, "OUTPUT", "rule-%s-OUTPUT" % idendpoint)
    _ipt_delete_chain(table, "rule-%s-OUTPUT" % idendpoint)

    _ipt_unlink_chains(table, "POSTROUTING", "rule-%s-POSTROUTING" % idendpoint)
    _ipt_delete_chain(table, "rule-%s-POSTROUTING" % idendpoint)

    _ipt_unlink_chains(table, "PREROUTING", "rule-%s-PREROUTING" % idendpoint)
    _ipt_delete_chain(table, "rule-%s-PREROUTING" % idendpoint)
    table.commit()
    table.autocommit = True
    return True

def _ipt_find_endpointchains_and_remove():
    '''
    This method tries to find rules that seem to have been created by the ipfloater, and deletes them. The rules seem to be created
      by the floater if they have the form rule-XXX-OUTPUT, rule-XXX-PREROUTING and rule-XXX-POSTROUTING. The ipfloater will only
      delete the rules if it can find the three rules that would correspond to a endpoint.
    '''
    table = iptc.Table(iptc.Table.NAT)
    table.refresh()

    chains = [ chain.name for chain in table.chains ]
    chains_output = [ chainname for chainname in chains if (chainname[-7:]=="-OUTPUT") and (chainname[:5]=="rule-")]
    
    # Now we are going to check wether the chains refer to a rule created by us or not
    chains_to_delete = []
    for chainname in chains_output:
        idendpoint = chainname[5:-7]
        if (("rule-%s-PREROUTING" % idendpoint) in chains) and (("rule-%s-POSTROUTING" % idendpoint) in chains):
            chains_to_delete.append(idendpoint)
        else:
            _LOGGER.warning("I found the chain %s that seems to be mine, but I cannot find some of the other chains that I would have created" % chainname)
            
    for idendpoint in chains_to_delete:
        _ipt_remove_endpointchains(idendpoint)

class Endpoint(object):
    @staticmethod
    def get_id():
        return str(uuid.uuid4())[:8]

    def __init__(self, public_ip, public_port, private_ip, private_port):
        self.id = Endpoint.get_id()
        self.public_ip = public_ip
        self.public_port = public_port
        self.private_ip = private_ip
        self.private_port = private_port

    def iptables_remove(self):
        '''
        This method executes the needed funtions to remove the iptables rules that will make possible the redirection stated by the endpoint.
          The method relies on the name of the rules created, and uses the names with which the rules are supposed to have been created, in
          order to delete them. This method does not check any of the parameters of the rules.
        '''
        return _ipt_remove_endpointchains(self.id)

    def iptables_apply(self):
        '''
        This method executes the needed funtions to create the iptables rules that will make possible the redirection stated by the endpoint.
          The method is able to detect wether the names of the rules are already occupied or not. If the names needed for the rules are occuppied,
          depending on the configuration, the method will delete the existing rules or not.
        '''
        result, msg = True, ""
        table = iptc.Table(iptc.Table.NAT)
        table.refresh()
        table.autocommit = False
        rule_return = iptc.Rule()
        rule_return.target = iptc.Target(rule_return, "RETURN")

        try:
            # OUTPUT Rules
            if (_ipt_chain_exists(table, "rule-%s-OUTPUT" % self.id)):
                if OVERWRITE_RULES:
                    _ipt_unlink_chains(table, "OUTPUT", "rule-%s-OUTPUT" % self.id)
                    _ipt_delete_chain(table, "rule-%s-OUTPUT" % self.id)
                else:
                    msg = string_and_log("chain rule-%s-OUTPUT already exists" % self.id, logging.WARNING)
                    raise Exception(msg)
            if (_ipt_chain_exists(table, "rule-%s-PREROUTING" % self.id)):
                if OVERWRITE_RULES:
                    _ipt_unlink_chains(table, "PREROUTING", "rule-%s-PREROUTING" % self.id)
                    _ipt_delete_chain(table, "rule-%s-PREROUTING" % self.id)
                else:
                    msg = string_and_log("chain rule-%s-PREROUTING already exists" % self.id, logging.WARNING)
                    raise Exception(msg)
            if (_ipt_chain_exists(table, "rule-%s-POSTROUTING" % self.id)):
                if OVERWRITE_RULES:
                    _ipt_unlink_chains(table, "POSTROUTING", "rule-%s-POSTROUTING" % self.id)
                    _ipt_delete_chain(table, "rule-%s-POSTROUTING" % self.id)
                else:
                    msg = string_and_log("chain rule-%s-POSTROUTING already exists" % self.id, logging.WARNING)
                    raise Exception(msg)
            
            chain_out = table.create_chain("rule-%s-OUTPUT" % self.id)
            rule_out = iptc.Rule()
            
            if self.private_port != 0:
                rule_out.protocol = "tcp"
                match = iptc.Match(rule_out, "tcp")
                match.dport = str(self.public_port)
                rule_out.add_match(match)
                
            rule_out.dst = "%s/32" % self.public_ip
            rule_out.target = rule_out.create_target("DNAT")
            if self.public_port == 0:
                rule_out.target.to_destination = self.private_ip
            else:
                rule_out.target.to_destination = "%s:%d" % (self.private_ip, self.private_port)

            chain_out.insert_rule(rule_return)
            chain_out.insert_rule(rule_out)
            _ipt_link_chains(table, "OUTPUT", "rule-%s-OUTPUT" % self.id)

            # PREROUTING RULES
            chain_pre = table.create_chain("rule-%s-PREROUTING" % self.id)
            chain_pre.insert_rule(rule_return)
            chain_pre.insert_rule(rule_out)
            _ipt_link_chains(table, "PREROUTING", "rule-%s-PREROUTING" % self.id)

            # POSTROUTING RULES
            chain_post = table.create_chain("rule-%s-POSTROUTING" % self.id)
            rule_post = iptc.Rule()
            
            if self.public_port != 0:
                rule_post.protocol = "tcp"
                match = iptc.Match(rule_post, "tcp")
                match.dport = str(self.private_port)
                rule_post.add_match(match)
                
            rule_post.src = "%s/32" % self.private_ip
            rule_post.target = rule_post.create_target("SNAT")

            if self.public_port == 0:
                rule_post.target.to_source = self.public_ip
            else:
                rule_post.target.to_source = "%s:%d" % (self.public_ip, self.public_port)
            chain_post.insert_rule(rule_return)
            chain_post.insert_rule(rule_post)
            _ipt_link_chains(table, "POSTROUTING", "rule-%s-POSTROUTING" % self.id)

            table.commit()
            table.autocommit = True
        except:
            result = False

        return result, msg

    def text_rules(self, new = True):
        '''
        This method outputs in text mode the rules that are needed to create the redirections that implement the endpoint.
          In case that new is False, the output will be the instructions needed to remove the endpoint. The output of the
          method can be issued to the commandline. 
        '''
        
        head = "\
iptables -t nat -N rule-%s-OUTPUT\n\
iptables -t nat -N rule-%s-PREROUTING\n\
iptables -t nat -N rule-%s-POSTROUTING\n\
iptables -t nat -A OUTPUT -j rule-%s-OUTPUT\n\
iptables -t nat -A PREROUTING -j rule-%s-PREROUTING\n\
iptables -t nat -A POSTROUTING -j rule-%s-POSTROUTING\n\
" % (self.id, self.id, self.id, self.id, self.id, self.id)
        bottom = "\
iptables -t nat -D OUTPUT -j rule-%s-OUTPUT\n\
iptables -t nat -D PREROUTING -j rule-%s-PREROUTING\n\
iptables -t nat -D POSTROUTING -j rule-%s-POSTROUTING\n\
iptables -t nat -X rule-%s-OUTPUT\n\
iptables -t nat -X rule-%s-PREROUTING\n\
iptables -t nat -X rule-%s-POSTROUTING\
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
            rule1 = "iptables -t nat %s rule-%s-OUTPUT -d %s/32 -j DNAT --to-destination %s" % (action, self.id, self.public_ip, self.private_ip)
            rule1b = "iptables -t nat %s rule-%s-OUTPUT -j RETURN" % (action, self.id)
            
            # regla de si me viene desde fuera y el destino es la ip publica y el puerto indicado, que me haga DNAT cambiando el destino a la IP privada y el puerto redirigido
            rule2 = "iptables -t nat %s rule-%s-PREROUTING -d %s/32 -j DNAT --to-destination %s" % (action, self.id, self.public_ip, self.private_ip)
            rule2b = "iptables -t nat %s rule-%s-PREROUTING -j RETURN" % (action, self.id)
            
            rule3 = "iptables -t nat %s rule-%s-POSTROUTING -s %s/32 -j SNAT --to-source %s" % (action, self.id, self.private_ip, self.public_ip)
            rule3b = "iptables -t nat %s rule-%s-POSTROUTING -j RETURN" % (action, self.id)
        else:
            # regla desde dentro, hacia dentro (para que no salga fuera de la red)
            rule1 = "iptables -t nat %s rule-%s-OUTPUT -d %s/32 -p tcp --dport %d -j DNAT --to-destination %s:%d" % (action, self.id, self.public_ip, self.public_port, self.private_ip, self.private_port)
            rule1b = "iptables -t nat %s rule-%s-OUTPUT -j RETURN" % (action, self.id)
            
            # regla de si me viene desde fuera y el destino es la ip publica y el puerto indicado, que me haga DNAT cambiando el destino a la IP privada y el puerto redirigido
            rule2 = "iptables -t nat %s rule-%s-PREROUTING -d %s/32 -p tcp --dport %d -j DNAT --to-destination %s:%d" % (action, self.id, self.public_ip, self.public_port, self.private_ip, self.private_port)
            rule2b = "iptables -t nat %s rule-%s-PREROUTING -j RETURN" % (action, self.id)
            
            rule3 = "iptables -t nat %s rule-%s-POSTROUTING -s %s/32 -p tcp --sport %d -j SNAT --to-source %s:%d" % (action, self.id, self.private_ip, self.public_port, self.public_ip, self.public_port)
            rule3b = "iptables -t nat %s rule-%s-POSTROUTING -j RETURN" % (action, self.id)
        return "%s%s\n%s\n%s\n%s\n%s\n%s\n%s" % (head, rule1, rule1b, rule2, rule2b, rule3, rule3b, bottom)

    def __str__(self, ):
        return "%s:%d -> %s:%d" % (self.public_ip, self.public_port, self.private_ip, self.private_port)
    

class EndpointManager():
    '''
    This class manages the endpoints that have been created. The EndpointManager has a set of public IPs that can
      be used to redirect their ports to some private IPs. There is an special case, when an endpoint refers to the
      port 0. In that case, the whole traffic for the public IP will be redirected to the private IP.
      
    The data structure consists of two dicts of dicts. The first level is indexed by an IP address, while the second
      level is indexed by the port. The result is and endpoint. These two data structures are redundant to each other
      but they are created in order to ease the management and readness of the code.
      
    Features:
      * A public IP MUST have an entry in the _public2private data structure. Otherwise, it will not be considered
      * A private IP that has not any entry in the _private2public data structure is not managed by the manager and
        that means that there is not any redirection for it.
    '''
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
        '''
        This method adds a new public ip to the pool of public ips that are available for redirections
        '''
        if ip in self._public2private:
            return True

        self._public2private[ip] = {}
        
    def _select_public_ip(self, private_ip, private_port, public_port = -1):
        '''
        This method is used to obtain an IP that can be used to implement the redirection. The result will be an endpoint
          that consist of a PublicIP:public_port -> private_ip:private_port. The method will fail in case that there are
          not any free public IPs for the endpoint.
        '''
        if public_port < 0:
            public_port = private_port
        
        if ((public_port == 0) and (private_port != 0)) or ((private_port == 0) and (public_port != 0)):
            return None, string_and_log("Requested one port to all endpoint. It is only possible to forward one-to-one or all-to-all", logging.ERROR)
        
        selected_ip = None
        if private_port == 0:
            # Let's check whether the internal IP is also redirected
            if private_ip in self._private2public:
                if 0 not in self._private2public[private_ip]:
                    # TODO: include an option to consider ip forwarding even if there are existing rules: i.e. clean the existing rules                    
                    return None, string_and_log("The IP %s has some ports redirected" % private_ip, logging.ERROR)
                else:
                    ep = self._private2public[private_ip][0]
                    selected_ip = ep.public_ip
            else:
                # let's look for a free IP
                free_ips = [ ip for ip in self._public2private if len(self._public2private[ip]) == 0 ]
                if len(free_ips) == 0:
                    # could not find a free IP
                    return None, string_and_log("could not find a free public IP")
                else:
                    # TODO: implement different policies: random, prioritized, round robbin, etc.
                    selected_ip = free_ips[random.randint(0, len(free_ips) - 1)]
        else:
            public_ips = {}
            if private_ip in self._private2public:
                if 0 in self._private2public[private_ip]:
                    ep = (self._private2public[private_ip])[0]
                    return None, string_and_log("requested a public ip for %s:%d while the whole ip is redirected from %s" % (private_ip, private_port, ep.public_ip), logging.WARNING)

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
                return None, string_and_log("requested a redirection for %s:%d but we have not free public ips" % (private_ip, private_port), logging.WARNING)
            
            ip_sorted = sorted(ip_list, key = lambda ip : ip[1])
            (selected_ip, _) = ip_sorted[0]
        
        return Endpoint(selected_ip, public_port, private_ip, private_port), ""
    
    def _add_ep(self, endpoint):
        '''
        This method stores an endpoint in the manager. WARNING: this method overwrites the existing peers (i.e. does
        not check whether they are occupied or not).
        '''
        if endpoint is None:
            return False
        
        if endpoint.public_ip not in self._public2private:
            return False, string_and_log("tried to redirect a public ip that it is not managed by us", logging.ERROR)
        
        if endpoint.private_ip not in self._private2public:
            self._private2public[endpoint.private_ip] = {}
            
        self._private2public[endpoint.private_ip][endpoint.private_port] = endpoint
        self._public2private[endpoint.public_ip][endpoint.public_port] = endpoint
        
        return True
    
    def _remove_ep(self, endpoint):
        '''
        This method removes an endpoint from the manager, if it exists.
        '''
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
        '''
        This method check whether there is a redirection to private_ip:private_port and returns it
        '''
        if private_ip not in self._private2public:
            return None
        
        if private_port not in self._private2public[private_ip]:
            return None
        
        return (self._private2public[private_ip])[private_port]

    def _get_ep_from_public(self, public_ip, public_port):
        '''
        This method check whether there is a redirection from public_ip:public_port and returns it
        '''
        if public_ip not in self._public2private:
            return None
        
        if public_port not in self._public2private[public_ip]:
            return None
        
        return (self._public2private[public_ip])[public_port]
    
    def _check_availability(self, ep_list, ip, port, consider_available_if_ip_not_exists = True):
        '''
        This method checks whether an ip and a port are available for redirection (i.e. are not in the data
          structure). This is an internal method used to manage the data structures in a generic manner, so
          it is needed the latter parameter to differentiate between the public and the private data structures:
          in the case of the public IPs, if it does not exist an entry in the data structure, it means that
          it is not available (in the case of private IPs, the non existence means that it is fully available).
        '''
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
        '''
        This method return True in case that the public_ip and public_port are available for redirection
          (i.e. the pair public_ip:public_port is not occupied, nor the ip is fully redirected (port 0))
        '''
        return self._check_availability(self._public2private, public_ip, public_port, False)

    def _private_available(self, private_ip, private_port):
        '''
        This method return True in case that the private_ip and private_port are available for redirection
          (i.e. the pair private_ip:private_port is not occupied, nor the ip is fully redirected (port 0))
        '''
        return self._check_availability(self._private2public, private_ip, private_port, True)

    def _remove_eps_from_list(self, ep_list):
        '''
        This method removes a set of endpoints from the manager. The list is in fact a dictionary of eps,
          indexed by the port number.
        '''
        ep_list = [ ep for _,ep in ep_list.items() ]
        error = False
        for ep in ep_list:
            if not self._remove_ep(ep):
                error = True
                _LOGGER.error("failed to remove endpoint: %s" % ep)
        return (not error)
    
    def _get_ep(self, ep):
        '''
        This method returns the ep, in case that it exists. 
        '''
        ex_ep = self._get_ep_from_private(ep.private_ip, ep.private_port)
        if (ex_ep.public_ip != ep.public_ip) or (ex_ep.public_port != ep.public_port):
            return None
        return ex_ep
    
    def apply_endpoint(self, ep):
        '''
        This function applies an endpoint (if it is possible), and stores it in the data structures.
        '''        
        if not self._private_available(ep.private_ip, ep.private_port):            
            return False, string_and_log("tried to apply a redirection to %s:%d but it is already occupied" % (ep.private_ip, ep.private_port), logging.WARNING)

        if not self._public_available(ep.public_ip, ep.public_port):
            return False, string_and_log("tried to apply a redirection from %s:%d but it is either occupied or the ip is not managed by ipfloater" % (ep.public_ip, ep.public_port), logging.WARNING)
        
        result, msg = ep.iptables_apply()
        if result:
            self._add_ep(ep)
            return True, ""
        else:
            return False, msg
    
    def request_endpoint(self, private_ip, private_port, public_port = -1):
        '''
        This function requests an IP for a pair private_ip:private_port, and returns the corresponding endpoint.
        '''        
        if not self._private_available(private_ip, private_port):
            return None, string_and_log("requesting a redirection to %s:%d, but it is already occupied" % (private_ip, private_port), logging.WARNING)
        
        return self._select_public_ip(private_ip, private_port, public_port)
        
    def terminate_redirection(self, private_ip, private_port):
        '''
        This function deletes the redirection to the private_ip:private_port, if it exists.
        '''
        ep = self._get_ep_from_private(private_ip, private_port)
        if ep is None:
            return False
        
        return self._remove_ep(ep)

    def free_endpoint(self, ep):
        '''
        This function deletes the redirection stated by an endpoint, in case that it exists
        '''
        if self._get_ep(ep) is None:
            return False, string_and_log("tried to remove and endpoint that does not exist %s" % ep, logging.WARNING)
        
        return True, string_and_log("endpoint %s successfully removed" % ep)
    
    def clean_private_ip(self, private_ip):
        '''
        This function deletes all the redirections that point to any port of a specific private ip
        '''
        if private_ip not in self._private2public:
            return True, string_and_log("ip %s was not managed by me, so I should consider that it is clean" % private_ip)
        return self._remove_eps_from_list(self._private2public[private_ip]), string_and_log("endpoints successfully removed")
    
    def clean_public_ip(self, public_ip):
        '''
        This function deletes all the redirections that part from any port of a specific public ip
        '''
        if public_ip not in self._public2private:
            return False, string_and_log("tried to remove redirections from ip %s but it is not managed by me" % public_ip)
        return self._remove_eps_from_list(self._public2private[public_ip]), string_and_log("endpoints successfully removed")
    
_ENDPOINT_MANAGER = None

def query_endpoint(dst_ip, dst_port, register = True):
    '''
    '''
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"
    
    ep, info = _ENDPOINT_MANAGER.request_endpoint(dst_ip, dst_port)
    if ep is None:
        return False, "Could not obtain a redirection for %s:%d (%s)" % (dst_ip, dst_port, info)
    
    if register:
        result, msg = _ENDPOINT_MANAGER.apply_endpoint(ep)
        if not result:
            return False, "Could not apply the redirection %s (%s)" % (ep, msg)

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

def get_version():
    return version.get()

def get_redirections():
    return str(_ENDPOINT_MANAGER)

if __name__ == '__main__':
    logging.basicConfig(filename=None,level=logging.DEBUG)
    eventloop.create_eventloop(True)
    
    ap = CmdLineParser("ipfloater", "This is a server that deals with iptables to enable floating IPs in private networks", [
        Flag("--remove-endpoints", "-r", "Remove the endpoints that are in the iptables tables that seem to have been created in other session", default = False),
        Parameter("--db-file", "-d", "The path for the persistence file", 1, False, "ipfloater.db"),
        Parameter("--listen-ip", "-i", "The ip adress in which ipfloater will listen", 1, False, ["127.0.0.1"]),
        Parameter("--listen-port", "-p", "The ip port in which ipfloater will listen", 1, False, [7000]),
    ])

    parsed, result, info = ap.parse(sys.argv[1:])
    if not parsed:
        if (result is None):
            print "Error:", info
            sys.exit(-1)
        else:
            print info
            sys.exit(0)

    SERVER=result.values['--listen-ip'][0]
    PORT=result.values['--listen-port'][0]
    REMOVE_RULES_AT_BOOT=result.values['--remove-endpoints']
    
    _ENDPOINT_MANAGER = EndpointManager("")
    
    # TODO: load configuration (IP Addresses, listen IP and port, Overwritting rules)
    # TODO: persist in database
    _ENDPOINT_MANAGER.add_public_ip("150.0.0.1")
    _ENDPOINT_MANAGER.add_public_ip("150.0.0.2")
    
    if not xmlrpcutils.create_xmlrpc_server_in_thread(SERVER, PORT, [query_endpoint, unregister_endpoint, clean_private_ip, clean_public_ip, get_version, get_redirections]):
        _LOGGER.error("could not setup the service")
        raise Exception("could not setup the service")

    if REMOVE_RULES_AT_BOOT:
        _ipt_find_endpointchains_and_remove()

    _LOGGER.info("server running in %s:%d" % (SERVER, PORT))

    #global _DATABASE
    #_DATABASE = db.DB.create_from_string("sqlite://./floatip.db")
    #if _DATABASE is None:
    #    raise Exception("could not connect to the database")
    #
    #_LOGGER.debug("connecting to the database")    
    #_DATABASE.connect()
    
    eventloop.get_eventloop().loop()
