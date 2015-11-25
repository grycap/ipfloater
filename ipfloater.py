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
from cpyutils.parameters import CmdLineParser, Flag, Parameter, Argument, Operation
import cpyutils.eventloop as eventloop
import cpyutils.db as db
import cpyutils.log
import cpyutils.xmlrpcutils as xmlrpcutils
import logging
import version

_LOGGER = cpyutils.log.Log("IPFLOATER")

def main_function():
    logging.basicConfig(filename=None,level=logging.DEBUG)
    eventloop.create_eventloop(True)

    class IPFloaterCmdLine(CmdLineParser):
        def preops(self, result, error):
            SERVER=result.values['--server-ip'][0]
            PORT=result.values['--server-port'][0]
            self._XMLRPC_SERVER = xmlrpcutils.ServerProxy("http://%s:%d" % (SERVER, PORT))

        def ippool(self, parse_result, error):
            try:
                _, ips = self._XMLRPC_SERVER.get_public_ips()
                return True, "IP Pool:\n%s\n%s" % ("-"*40, ", ".join(ips))
            except:
                return False, "Could not contact the server"

        def getip(self, parse_result, error):
            result, ep = self._XMLRPC_SERVER.query_endpoint(parse_result.values['ip'][0], 0)
            if result:
                return True, "Public IP obtained: %s" % ep['public_ip']
            else:
                return False, "Could not obtain a redirection (server responded: %s)" % ep
        
        def releaseip(self, parse_result, error):
            ip = parse_result.values['ip'][0]
            result, ep = self._XMLRPC_SERVER.clean_public_ip(ip)
            if result:
                return True, "Released the redirection to IP %s" % (ip)
            else:
                return False, "Could not release the redirectino to IP %s (server responded: %s)" % (ip, ep)
        
        def status(self, result, error):
            try:
                return True, "Table of redirections:\n%s\n%s" % ("-"*40, self._XMLRPC_SERVER.get_redirections())
            except:
                return False, "Could not contact the server"

        def version(self, result, error):
            try:
                server_version = self._XMLRPC_SERVER.get_version()
                return True, "Client version: %s\nServer version: %s" % (version.get(), server_version)
            except:
                return True, "Client version: %s\nCould not contact server" % version.get()
    
    ap = IPFloaterCmdLine("ipfloater", "This the client for ipfloaterd, which is a server that deals with iptables to enable floating IPs in private networks", [
        Parameter("--server-ip", "-i", "The ip adress in which ipfloater listens", 1, False, ["127.0.0.1"]),
        Parameter("--server-port", "-p", "The ip port in which ipfloater listens", 1, False, [7000]),
            Operation("getip", desc = "Requests a floating IP for a private IP", arguments = [
                Argument("ip", "private ip address to which is requested the floating ip", mandatory = True, count = 1),
            ]),
            Operation("releaseip", desc = "Releases the floating IP to a private IP", arguments = [
                Argument("ip", "private ip address to which is granted the floating ip", mandatory = True, count = 1),
            ]),
            Operation("status", desc = "Gets the status of the redirections"),
            Operation("version", desc = "Gets the version of the client and the server"),
            Operation("ippool", desc = "Gets the public ip addresses in the pool"),
    ])

    ap.self_service(True)
    
if __name__ == '__main__':
    main_function()