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
import sys
import version
from cpyutils.parameters import CmdLineParser, Flag, Parameter, Argument
import cpyutils.eventloop as eventloop
import cpyutils.db as db
import cpyutils.xmlrpcutils as xmlrpcutils
import cpyutils.log
import cpyutils.config
import endpoint
import config
import iptables

'''
In the awful case that a uuid already exists in the iptables table, how should the endpoint proceed? The
  OVERWRITE_RULES flag states wether to overwrite the rule or raise an error.
  - perhaps a new id should be generated? (this could happen although statiscally has a low probability)
  - this flag in inherited from when sequential numbers were used for ids and all started at 0 at boot
'''
OVERWRITE_RULES=True

_LOGGER = cpyutils.log.Log("IPFLOATER")
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

def get_public_ips():
    if _ENDPOINT_MANAGER is None:
        return False, "Endpoint Manager not found"

    return True, _ENDPOINT_MANAGER.get_public_ips()

def get_version():
    return version.get()

def get_redirections():
    return str(_ENDPOINT_MANAGER)

def main_loop():
    eventloop.create_eventloop(True)
    
    ap = CmdLineParser("ipfloater", "This is a server that deals with iptables to enable floating IPs in private networks", [
        Flag("--remove-endpoints", "-r", "Remove the endpoints that are in the iptables tables that seem to have been created in other session", default = config.config.REMOVE_AT_BOOT),
        Parameter("--db", "-d", "The path for the persistence file", 1, False, [config.config.DB]),
        Parameter("--listen-ip", "-i", "The ip adress in which ipfloater will listen", 1, False, [ config.config.LISTEN_IP ]),
        Parameter("--listen-port", "-p", "The ip port in which ipfloater will listen", 1, False, [ config.config.LISTEN_PORT ]),
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
    
    _ENDPOINT_MANAGER = endpoint.EndpointManager(result.values['--db'][0])
    
    # TODO: persist in database
    for ip in config.config.IP_POOL:
        _ENDPOINT_MANAGER.add_public_ip(ip)
    
    if not xmlrpcutils.create_xmlrpc_server_in_thread(SERVER, PORT, [query_endpoint, unregister_endpoint, clean_private_ip, clean_public_ip, get_version, get_redirections, get_public_ips]):
        _LOGGER.error("could not setup the service")
        raise Exception("could not setup the service")

    if REMOVE_RULES_AT_BOOT:
        iptables.find_endpointchains_and_remove()
        
    _ENDPOINT_MANAGER.get_data_from_db()
    _LOGGER.info("server running in %s:%d" % (SERVER, PORT))

    eventloop.get_eventloop().loop()

if __name__ == '__main__':
    main_loop()
