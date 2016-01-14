# coding: utf-8
#
# Floating IP Addresses manager (IPFloater)
# Copyright (C) 2015 - GRyCAP - Universitat Politecnica de Valencia
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
import logging
import random
import uuid
import cpyutils.log
import iptables
import cpyutils.db
import iptc
import time
import cpyutils.iputils

_LOGGER = cpyutils.log.Log("ep")

class Endpoint(object):
    @staticmethod
    def get_id():
        return str(uuid.uuid4())[:6]

    def to_json(self):
        return {'id': self.id,
                'public_ip': self.public_ip,
                'public_port': self.public_port,
                'private_ip': self.private_ip,
                'private_port': self.private_port,
                'timestamp': self.timestamp}

    def __str__(self):
        if self.public_port == 0:
            return "%s -> %s" % (self.public_ip, self.private_ip)
        else:
            return "%s:%s -> %s:%s" % (self.public_ip, self.public_port, self.private_ip, self.private_port)
        return str(self.to_json())

    def __init__(self, public_ip, public_port, private_ip, private_port):
        self.id = Endpoint.get_id()
        self.public_ip = public_ip
        self.public_port = int(public_port)
        self.private_ip = private_ip
        self.private_port = int(private_port)
        self.timestamp = time.time()

    def iptables_remove(self):
        '''
        This method executes the needed funtions to remove the iptables rules that will make possible the redirection stated by the endpoint.
          The method relies on the name of the rules created, and uses the names with which the rules are supposed to have been created, in
          order to delete them. This method does not check any of the parameters of the rules.
        '''
        return iptables.remove_endpointchains(self.id)

    def iptables_apply(self):
        '''
        This method executes the needed funtions to create the iptables rules that will make possible the redirection stated by the endpoint.
          The method is able to detect wether the names of the rules are already occupied or not. If the names needed for the rules are occuppied,
          depending on the configuration, the method will delete the existing rules or not.
          
        # solucion de nat loopback: en postrouting, si el source es la LAN y el destino es     
        # iptables -t nat -A ipfl-rule-0-POSTROUTING -s 10.3.0.5/24 -d 10.3.0.5/32 -p tcp --dport 22 -j SNAT --to-source 10.0.0.69
        '''
        result, msg = True, ""
        table = iptc.Table(iptc.Table.NAT)
        table.refresh()
        table.autocommit = False
        rule_return = iptc.Rule()
        rule_return.target = iptc.Target(rule_return, "RETURN")

        if True:
            # OUTPUT Rules
            if (iptables.chain_exists(table, "ipfl-rule-%s-OUTPUT" % self.id)):
                if OVERWRITE_RULES:
                    iptables.unlink_chains(table, "ipfloater-OUTPUT", "ipfl-rule-%s-OUTPUT" % self.id)
                    iptables.delete_chain(table, "ipfl-rule-%s-OUTPUT" % self.id)
                else:
                    msg = _LOGGER.log("chain ipfl-rule-%s-OUTPUT already exists" % self.id, logging.WARNING)
                    raise Exception(msg)
            if (iptables.chain_exists(table, "ipfl-rule-%s-PREROUTING" % self.id)):
                if OVERWRITE_RULES:
                    iptables.unlink_chains(table, "ipfloater-PREROUTING", "ipfl-rule-%s-PREROUTING" % self.id)
                    iptables.delete_chain(table, "ipfl-rule-%s-PREROUTING" % self.id)
                else:
                    msg = _LOGGER.log("chain ipfl-rule-%s-PREROUTING already exists" % self.id, logging.WARNING)
                    raise Exception(msg)
            if (iptables.chain_exists(table, "ipfl-rule-%s-POSTROUTING" % self.id)):
                if OVERWRITE_RULES:
                    iptables.unlink_chains(table, "ipfloater-POSTROUTING", "ipfl-rule-%s-POSTROUTING" % self.id)
                    iptables.delete_chain(table, "ipfl-rule-%s-POSTROUTING" % self.id)
                else:
                    msg = _LOGGER.log("chain ipfl-rule-%s-POSTROUTING already exists" % self.id, logging.WARNING)
                    raise Exception(msg)
            
            chain_out = table.create_chain("ipfl-rule-%s-OUTPUT" % self.id)
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

            chain_out.append_rule(rule_out)
            # chain_out.append_rule(rule_return)
            iptables.link_chains(table, "ipfloater-OUTPUT", "ipfl-rule-%s-OUTPUT" % self.id)

            # PREROUTING RULES
            chain_pre = table.create_chain("ipfl-rule-%s-PREROUTING" % self.id)
            chain_pre.append_rule(rule_out)
            # chain_pre.append_rule(rule_return)
            iptables.link_chains(table, "ipfloater-PREROUTING", "ipfl-rule-%s-PREROUTING" % self.id)

            # POSTROUTING RULES
            chain_post = table.create_chain("ipfl-rule-%s-POSTROUTING" % self.id)
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
            chain_post.append_rule(rule_post)
            #chain_post.append_rule(rule_return)
            iptables.link_chains(table, "ipfloater-POSTROUTING", "ipfl-rule-%s-POSTROUTING" % self.id)

            table.commit()
            table.autocommit = True
        try:
            pass
        except:
            result = False

        return result, msg

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
        self._dbstring = db_string
        self._private_ip_ranges = []
        result, _ = self._initialize_db()
    
    def _ip_in_ranges(self, ip):
        # We'll check if the ip is in any of the ranges controlled by the manager
        for (mask_ip, mask) in self._private_ip_ranges:
            if cpyutils.iputils.ip_in_ip_mask(ip, mask_ip, mask):
                return True
        return False
    
    def __str__(self):
        retval = ""
        for ip in self._public2private:
            for _, ep in self._public2private[ip].items():
                retval = "%s%s\n" % (retval, ep)
        return retval
    
    def _initialize_db(self):
        if (self._dbstring == "") or (self._dbstring is None):
            return False, _LOGGER.info("not using a database (no db connection string provided)")
        db = cpyutils.db.DB.create_from_string(self._dbstring)
        if db is not None:
            succes, _, _ = db.sql_query("create table if not exists endpoint (id, public_ip, public_port, private_ip, private_port, timestamp)", True)
            if not succes:
                return False, _LOGGER.error("could not initialize the database")
            return True, ""
        else:
            _LOGGER.warning("Not using a database due to errors in the connection")
            self._dbstring = None

            return False, _LOGGER.warning("could not create a connection to the databse")
    
    def add_private_range(self, ipmask):
        try:
            mask_ip, mask = cpyutils.iputils.str_to_ipmask(ipmask)
        except:
            return False
        _LOGGER.log("range %s successfully added" % ipmask)
        self._private_ip_ranges.append((mask_ip, mask))
    
    def get_data_from_db(self):
        if self._dbstring is None:
            return False, ""
        
        db = cpyutils.db.DB.create_from_string(self._dbstring)
        if db is not None:
            success, rowcount, rows = db.sql_query("select * from endpoint", True)
            if success:
                bad_eps = []
                for row in rows:
                    _id, public_ip, public_port, private_ip, private_port, timestamp = row
                    ep = Endpoint(public_ip, public_port, private_ip, private_port)
                    ep.id = _id
                    ep.timestamp = timestamp
                    _LOGGER.debug("reading endpoint %s from the database" % ep)
                    result, msg = self.apply_endpoint(ep, False)
                    if not result:
                        _LOGGER.warning("ignoring (%s)" % msg)
                        bad_eps.append(ep)
                        
                # Cleaning bad endpoints
                for ep in bad_eps:
                    self._unsave_endpoint(ep)
                
                return True, "Reading %d endpoints" % rowcount
            else:
                return False, "Could not read endpoints from database"
        else:
            _LOGGER.warning("Not using a database due to errors in the connection")
            self._dbstring = None

            return False, _LOGGER.warning("could not create a connection to the databse")

    def _save_endpoint(self, ep):
        if self._dbstring is None:
            return False, ""

        db = cpyutils.db.DB.create_from_string(self._dbstring)
        if db is not None:
            success, rowcount, rows = db.sql_query(_LOGGER.debug("insert into endpoint values (\"%s\", \"%s\", %d, \"%s\", %d, %ld)" % (ep.id, ep.public_ip, ep.public_port, ep.private_ip, ep.private_port, ep.timestamp)), True)
            if success:
                return True, "Endpoint saved (%s)" % ep
            else:
                return False, "Could not save endpoint to the database"
        else:
            return False, _LOGGER.warning("could not create a connection to the databse")

    def _unsave_endpoint(self, ep):
        if self._dbstring is None:
            return False, ""

        db = cpyutils.db.DB.create_from_string(self._dbstring)
        if db is not None:
            success, rowcount, rows = db.sql_query(_LOGGER.debug("delete from endpoint where public_ip = \"%s\" and public_port = %d and private_ip = \"%s\" and private_port = %d" % (ep.public_ip, ep.public_port, ep.private_ip, ep.private_port)), True)
            if success:
                return True, "Endpoint removed from the database (%s)" % ep
            else:
                return False, "Could not delete endpoint from the database"
        else:
            return False, _LOGGER.warning("could not create a connection to the databse")

    
    def add_public_ip(self, ip):
        '''
        This method adds a new public ip to the pool of public ips that are available for redirections
        '''
        ip = cpyutils.iputils.check_ip(ip)
        if ip is None:
            return False
        
        if ip in self._public2private:
            return True

        self._public2private[ip] = {}
        return True
        
    def get_public_ips(self):
        return self._public2private.keys()
            
    def _add_ep(self, endpoint):
        '''
        This method stores an endpoint in the manager. WARNING: this method overwrites the existing peers (i.e. does
        not check whether they are occupied or not).
        '''
        if endpoint is None:
            return False
        
        if endpoint.public_ip not in self._public2private:
            return False, _LOGGER.log("tried to redirect a public ip that it is not managed by us", logging.ERROR)
        
        if not self._ip_in_ranges(endpoint.private_ip):
            return False, _LOGGER.log("tried to redirect to an ip that is not in any of the private ranges", logging.ERROR)
        
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
            
        # self._unsave_endpoint(endpoint)
            
        return True

    def get_ep_from_private(self, private_ip, private_port):
        '''
        This method check whether there is a redirection to private_ip:private_port and returns it
        '''
        if private_ip not in self._private2public:
            return None
        
        if private_port not in self._private2public[private_ip]:
            return None
        
        return (self._private2public[private_ip])[private_port]

    def get_ep_from_public(self, public_ip, public_port):
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
            if (len(ep_list[ip]) > 0) and (port == 0): return False
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
            result, _ = self.terminate_endpoint(ep)
            if not result:
                error = True
                _LOGGER.error("failed to remove endpoint: %s" % ep)
        return (not error)
    
    def _get_ep(self, ep):
        '''
        This method returns the ep, in case that it exists. 
        '''
        ex_ep = self.get_ep_from_private(ep.private_ip, ep.private_port)
        if (ex_ep.public_ip != ep.public_ip) or (ex_ep.public_port != ep.public_port):
            return None
        return ex_ep
    
    def apply_endpoint(self, ep, persist = True):
        '''
        This function applies an endpoint (if it is possible), and stores it in the data structures.
        * if presist is set to True it will be saved in the database. Otherwise it won't be (it should only be not persisted when it is loaded from the db)
        '''
        if (ep.public_port == 0 and ep.private_port != 0) or (ep.public_port != 0 and ep.private_port == 0):
            return False, _LOGGER.log("one-to-all redirections are not allowed")
        
        if not self._ip_in_ranges(ep.private_ip):
            return False, _LOGGER.log("tried to redirect to an ip that is not in any of the private ranges", logging.ERROR)
        
        if not self._private_available(ep.private_ip, ep.private_port):            
            return False, _LOGGER.log("tried to apply a redirection to %s:%d but it is already occupied" % (ep.private_ip, ep.private_port), logging.WARNING)

        if not self._public_available(ep.public_ip, ep.public_port):
            return False, _LOGGER.log("tried to apply a redirection from %s:%d but it is either occupied or the ip is not managed by ipfloater" % (ep.public_ip, ep.public_port), logging.WARNING)
        
        result, msg = ep.iptables_apply()
        if result:
            self._add_ep(ep)
            if persist:
                self._save_endpoint(ep)
            return True, ""
        else:
            return False, msg
    
    def request_endpoint(self, public_ip, public_port, private_ip, private_port):
        '''
        This function requests a redirection from public_ip:public_port to private_ip:private_port
        * public_ip and public_port can be set to None, and this method will try to find an option.
        
        @return values: possible endpoint list, reason (if the list is empty)
        '''
        # _LOGGER.log("%s:%s -> %s:%s" % (public_ip, public_port, private_ip, private_port))
        if cpyutils.iputils.check_ip(private_ip) is None:
            return [], _LOGGER.log("bad private IP format (%s)" % private_ip, logging.ERROR)
            
        if not self._ip_in_ranges(private_ip):
            return [], _LOGGER.log("tried to redirect to an ip that is not in any of the private ranges", logging.ERROR)

        if private_ip is None or private_port is None:
            return [], _LOGGER.log("requesting an incorrect redirection to %s:%d" % (private_ip, private_port), logging.WARNING)

        if not self._private_available(private_ip, private_port):
            return [], _LOGGER.log("requested a redirection to %s:%s but it is already occupied" % (private_ip, private_port), logging.WARNING)
        
        if (private_port == 0) and (public_port is None):
            public_port = private_port

        try:
            if public_port is not None:
                public_port = int(public_port)
            private_port = int(private_port)
        except:
            return [], _LOGGER.log("incorrect port format (it must be an integer)", logging.ERROR)
        
        if ((private_port == 0) and (public_port != 0)) or ((private_port != 0) and (public_port == 0)):
            return [], _LOGGER.log("requested a redirection to a whole IP but stated a single public port... only all-to-all or one-to-one redirections are allowed", logging.WARNING)
        
        preferred = []
        if public_ip is None:
            # Let's check from which IPs has been redirected the private IP
            ip_list = []
            if private_ip in self._private2public:
                public_ips = {}
                eps = self._private2public[private_ip]
                for port, ep in eps.items():
                    if ep.public_ip not in public_ips:
                        public_ips[ep.public_ip] = 0
                    public_ips[ep.public_ip]+=1
                    
                ip_list = [ (ip, public_ips[ip]) for ip in public_ips ]
                ip_sorted = sorted(ip_list, key = lambda ip : ip[1])
                ip_list = [ ip for (ip, _) in ip_sorted ]

            # If any of the already assigned IP has the private port free, we'll use it
            wanted_port = public_port
            if wanted_port is None:
                wanted_port = private_port
                
            # Let's make two lists of the possible IP:port pairs.
            # - possible_endpoints are the possible endpoints in which the desired port is free for the IP
            # - other_possible_endpoints are some other endpoints which are free, but the desired port was not free and other port is provided
            possible_endpoints = []
            other_possible_endpoints = []
            for ip in ip_list + [ ip for ip in self._public2private if ip not in ip_list ]:
                eps = self._public2private[ip]
                if 0 not in eps:
                    if wanted_port not in eps:
                        possible_endpoints.append(Endpoint(ip, wanted_port, private_ip, private_port))
                    else:
                        other_possible_endpoints.append(Endpoint(ip, self._assign_port(ip, wanted_port), private_ip, private_port))

            if public_port is None:
                # No matter which is the public IP nor the public port, so we'll provide some options
                if (len(possible_endpoints) == 0) and (len(other_possible_endpoints) == 0):
                    return [], _LOGGER.log("could not find any free ip or port")
                return possible_endpoints + other_possible_endpoints, ""
            else:
                # No matter which is the public IP but the public port is fixed
                if len(possible_endpoints) == 0:
                    return [], _LOGGER.log("could not find any free ip for that port")
                return possible_endpoints, ""
        else:
            if public_port is None:
                # The public IP is fixed, but the public port is not.
                if public_ip not in self._public2private:
                    return [], _LOGGER.log("requested a redirection from %s but the ip is not managed by ipfloater" % (public_ip), logging.WARNING)
                
                # We'll try to assign a port using the heuristics (the default assigns the desired port if it is free)
                public_port = self._assign_port(public_ip, private_port)
                
                return [ Endpoint(public_ip, public_port, private_ip, private_port)], ""
            else:
                # Both the public IP and the port are fixed, so we won't create the endpoint unless it is available
                if not self._public_available(public_ip, public_port):
                    return [], _LOGGER.log("requested a redirection from %s:%d but it is either occupied or the ip is not managed by ipfloater" % (public_ip, public_port), logging.WARNING)
                return [ Endpoint(public_ip, public_port, private_ip, private_port) ], ""
            
    def _assign_port(self, public_ip, wanted_port):
        '''
        This method is included as a particular mechanism to enable including heuristics to assign pseudorandom ports
          - eg. if wanted 80, try to deliver the 8080, or the 10080, etc.
        '''
        if wanted_port not in self._public2private[public_ip]:
            return wanted_port
        
        rand_port = random.randint(1025, 65535)
        while rand_port in self._public2private[public_ip]:
            rand_port = random.randint(1025, 65535)
        return rand_port
                    
    def terminate_redirection_to(self, private_ip, private_port):
        '''
        This function deletes the redirection to the private_ip:private_port, if it exists.
        '''
        ep = self.get_ep_from_private(private_ip, private_port)
        if ep is None:
            return False
        
        return self._remove_ep(ep)

    def terminate_redirection_from(self, public_ip, public_port):
        '''
        This function deletes the redirection from the public_ip:public_port, if it exists.
        '''
        ep = self.get_ep_from_public(public_ip, public_port)
        if ep is None:
            return False
        
        return self._remove_ep(ep)

    def terminate_endpoint(self, ep):
        '''
        This function deletes the redirection stated by an endpoint, in case that it exists
        '''
        if self._get_ep(ep) is None:
            return False, _LOGGER.log("tried to remove and endpoint that does not exist %s" % ep, logging.WARNING)
        
        result = ep.iptables_remove()
        if result:
            self._remove_ep(ep)
            self._unsave_endpoint(ep)
            return True, _LOGGER.log("endpoint %s successfully removed" % ep)
        else:
            return False, _LOGGER.log("failed to remove the iptables rules corresponding to %s" % ep)
    
    def clean_private_ip(self, private_ip):
        '''
        This function deletes all the redirections that point to any port of a specific private ip
        '''
        if private_ip not in self._private2public:
            return False, _LOGGER.log("ip %s was not managed by me, so I do not know how to clean it" % private_ip)
        return self._remove_eps_from_list(self._private2public[private_ip]), _LOGGER.log("endpoints successfully removed")
    
    def clean_public_ip(self, public_ip):
        '''
        This function deletes all the redirections that part from any port of a specific public ip
        '''
        if public_ip not in self._public2private:
            return False, _LOGGER.log("tried to remove redirections from ip %s but it is not managed by me" % public_ip)
        return self._remove_eps_from_list(self._public2private[public_ip]), _LOGGER.log("endpoints successfully removed")

    def get_endpoints(self, json = False):
        eps = {}
        for ip, endpoints in self._private2public.items():
            for _, ep in endpoints.items():
                eps[ep.id] = ep.to_json() if json else ep
            
        return eps
    
    def get_endpoints_from_public(self, json = False):
        eps = {}
        for ip, endpoints in self._public2private.items():
            redirs = {}
            for _, ep in endpoints.items():
                redirs[ep.public_port] = ep.to_json() if json else ep

            eps[ip] = redirs
            
        return eps
    
    def get_endpoints_from_private(self, json = False):
        eps = {}
        for ip, endpoints in self._private2public.items():
            redirs = {}
            for _, ep in endpoints.items():
                redirs[ep.private_port] = ep.to_json() if json else ep
            eps[ip] = redirs
            
        return eps