#! /usr/bin/env python
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
import config
import sys
import version
from cpyutils.parameters import CmdLineParser, Flag, Parameter, Argument
import cpyutils.eventloop as eventloop
import cpyutils.db as db
import cpyutils.xmlrpcutils as xmlrpcutils
import cpyutils.log
import cpyutils.config
import endpoint
import iptables
import arptable
import os
from cpyutils.iputils import check_ip
import signal

'''
In the awful case that a uuid already exists in the iptables table, how should the endpoint proceed? The
  OVERWRITE_RULES flag states wether to overwrite the rule or raise an error.
  - perhaps a new id should be generated? (this could happen although statiscally has a low probability)
  - this flag in inherited from when sequential numbers were used for ids and all started at 0 at boot
'''
OVERWRITE_RULES=True

_LOGGER = cpyutils.log.Log("IPFLOATER")

def get_endpoint_manager():
    global _ENDPOINT_MANAGER
    return _ENDPOINT_MANAGER

def get_arp_table():
    global _ARP_TABLE
    return _ARP_TABLE

_ENDPOINT_MANAGER = None
_ARP_TABLE = None

def query_endpoint(dst_ip, dst_port, register = True):
    '''
    '''
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"
    
    ep, info = _ENDPOINT_MANAGER.request_endpoint(None, None, dst_ip, dst_port)
    if len(ep) == 0:
        return False, "Could not obtain a redirection for %s:%d (%s)" % (dst_ip, dst_port, info)
    
    if register:
        ep = ep[0]
        result, msg = _ENDPOINT_MANAGER.apply_endpoint(ep)
        if not result:
            return False, "Could not apply the redirection %s (%s)" % (ep, msg)

    return True, ep

def unregister_redirection_to(dst_ip, dst_port):
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    result = _ENDPOINT_MANAGER.terminate_redirection_to(dst_ip, dst_port)
    if not result:
        return False, "Could not delete the redirection to %s:%d. Does it exist?" % (dst_ip, dst_port)
    
    return True, "Redirection %s unregistered" % ep

def unregister_redirection_from(public_ip, public_port):
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    result = _ENDPOINT_MANAGER.terminate_redirection_from(public_ip, public_port)
    if not result:
        return False, "Could not delete the redirection from %s:%d. Does it exist?" % (public_ip, public_port)
    
    return True, "Redirection %s unregistered" % ep

def unregister_redirection(public_ip, public_port, private_ip, private_port):
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    ep = Endpoint(public_ip, public_port, private_ip, private_port)
    result = _ENDPOINT_MANAGER.terminate_endpoint(ep)
    if not result:
        return False, "Could not delete the redirection %s. Does it exist?" % (str(ep))
    
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

def arp(mac):
    global _ARP_TABLE
    if _ARP_TABLE is None:
        return False, "ARP table not found"

    ip = _ARP_TABLE.get_ip(mac)
    if ip is None:
        return False, "Could not get the IP address for %s" % (mac)
    
    return True, ip

def get_public_ips():
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    return True, _ENDPOINT_MANAGER.get_public_ips()

def get_version():
    return version.get()

def get_redirections():
    return str(_ENDPOINT_MANAGER)

def handler_sigint(signal, frame):
    _LOGGER.info("removing iptables rules")
    iptables.find_endpointchains_and_remove()
    sys.exit(0)

def main_loop():
    global _ENDPOINT_MANAGER, _ARP_TABLE
    eventloop.create_eventloop(True)
    
    ap = CmdLineParser("ipfloater", "This is a server that deals with iptables to enable floating IPs in private networks", [
        Flag("--remove-endpoints", "-r", "Remove the endpoints that are in the iptables tables that seem to have been created in other session", default = config.config.REMOVE_AT_BOOT),
        Parameter("--db", "-d", "The path for the persistence file", 1, False, [config.config.DB]),
        Parameter("--listen-ip", "-i", "The ip adress in which ipfloater will listen for xmlrpc requests", 1, False, [ config.config.LISTEN_IP ]),
        Parameter("--listen-port", "-p", "The ip port in which ipfloater will listen for xmlrpc requests", 1, False, [ config.config.LISTEN_PORT ]),
        Parameter("--rest-ip", "-s", "The ip adress in which ipfloater will listen for restful requests", 1, False, [ config.config.REST_IP ]),
        Parameter("--rest-port", "-t", "The ip port in which ipfloater will listen for restful requests", 1, False, [ config.config.REST_PORT ]),
        Parameter("--arp-table", "-a", "The file that contains a set of whitespace separated pairs MAC IP that will be used to resolve arp requests. The IPs will also be added to the IP pool.", 1, False, [ config.config.IP_POOL_FILE ]),
    ])
    
    # Will try to exit removing the iptables rules
    signal.signal(signal.SIGINT, handler_sigint)
    signal.signal(signal.SIGTERM, handler_sigint)

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
    
    _ENDPOINT_MANAGER = endpoint.EndpointManager(result.values['--db'][0])
    
    _ARP_TABLE = arptable.ARPTable()
    arp_filename = result.values['--arp-table'][0]
    if arp_filename != "":
        arp_filename = os.path.expanduser(os.path.expandvars(arp_filename))
        if _ARP_TABLE.read_from_file(arp_filename) is not None:
            for ip in _ARP_TABLE.get_ips():
                _ENDPOINT_MANAGER.add_public_ip(ip)
            for ip in _ARP_TABLE.get_ips_without_mac():
                _ENDPOINT_MANAGER.add_public_ip(ip)
    
    # TODO: persist in database
    for ip in config.config.IP_POOL:
        _ENDPOINT_MANAGER.add_public_ip(ip)
        
    for ipmask in config.config.PRIVATE_IP_RANGES:
        _ENDPOINT_MANAGER.add_private_range(ipmask)
    
    if not xmlrpcutils.create_xmlrpc_server_in_thread(SERVER, PORT, [arp, query_endpoint, unregister_redirection, unregister_redirection_from, unregister_redirection_to, clean_private_ip, clean_public_ip, get_version, get_redirections, get_public_ips]):
        _LOGGER.error("could not setup the service")
        raise Exception("could not setup the service")

    if REMOVE_RULES_AT_BOOT:
        iptables.find_endpointchains_and_remove()
        
    _ENDPOINT_MANAGER.get_data_from_db()
    _LOGGER.info("server running in %s:%d" % (SERVER, PORT))

    RESTIP=result.values['--rest-ip'][0]
    RESTPORT=result.values['--rest-port'][0]
    try:
        RESTPORT = int(RESTPORT)
    except:
        RESTPORT = 0
        
    if (RESTIP is not None) and (RESTIP != "") and (RESTPORT > 0):
        import restserver
        import cpyutils.restutils
        cpyutils.restutils.run_in_thread(RESTIP, RESTPORT)
        _LOGGER.info("REST server running in %s:%d" % (RESTIP, RESTPORT))

    eventloop.get_eventloop().loop()

if __name__ == '__main__':
    main_loop()
