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
import cpyutils.restutils
import ipfloaterd

app = cpyutils.restutils.get_app()

@app.route('/')
def get_endpoints():
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    return cpyutils.restutils.response_json(_ENDPOINT_MANAGER.get_endpoints(True))

@app.route('/public')
def get_public_redirections():
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    return cpyutils.restutils.response_json(_ENDPOINT_MANAGER.get_endpoints_from_public(True))

@app.route('/public/:ip')
def get_public_redirections(ip):
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    eps = _ENDPOINT_MANAGER.get_endpoints_from_public(True)
    if ip in eps:
        return cpyutils.restutils.response_json(eps[ip])
    else:
        # we'll return an empty list to indicate that there is not any redirection
        #  this is to enable semantics for the /redirect/ predicate to create redirections
        return cpyutils.restutils.response_json({})

@app.route('/public/:ip/:port')
def get_public_redirections(ip, port):
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    try:
        port = int(port.strip("/"))
    except:
        return cpyutils.restutils.error(400, "Malformed request: port is an integer")
    
    eps = _ENDPOINT_MANAGER.get_endpoints_from_public(True)
    if (ip in eps) and (port in (eps[ip])):
        return cpyutils.restutils.response_json((eps[ip])[port])
    else:
        # we'll return an empty list to indicate that there is not any redirection
        #  this is to enable semantics for the /redirect/ predicate to create redirections
        return cpyutils.restutils.response_json({})

def create_public_redirection(ip_pub, port_pub, ip_priv, port_priv):
    '''
    This method requests a whole specific public IP to be redirected to a private IP
    '''
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    
    ep_list, info = _ENDPOINT_MANAGER.request_endpoint(ip_pub, port_pub, ip_priv, port_priv)
    if len(ep_list) == 0:
        return cpyutils.restutils.error(404, "Could not obtain a redirection for %s:%s\n%s" % (ip_priv, port_priv, info))
        # return False, "Could not obtain a redirection for %s:%d (%s)" % (ip_priv, port_priv, info)
    
    if len(ep_list) == 1:
        ep = ep_list[0]
        result, msg = _ENDPOINT_MANAGER.apply_endpoint(ep)
        if not result:
            return cpyutils.restutils.error(501, "An error ocurred when registering endpoing %s\n%s" % (str(ep), msg))
        else:
            cpyutils.restutils.set_status(201)
            cpyutils.restutils.add_header("Location", "/public/%s/%s" % (ep.public_ip, ep.public_port))
            return cpyutils.restutils.response_json(ep.to_json())
    else:
        eps = {}
        for ep in eplist:
            eps[ep.public_port] = ep.to_json()
        cpyutils.restutils.set_status(201)
        return cpyutils.restutils.response_json(eps)

@app.route('/public/:ip_pub/:port_pub/redirect/:ip_priv/:port_priv', method = 'PUT')
def create_public_redirection_ipp_ipp(ip_pub, port_pub, ip_priv, port_priv):
    # PUT {ip, port} (redirects "ip_pub:ip_port" to "ip_priv:port_priv")
    return create_public_redirection(ip_pub, port_pub, ip_priv, port_priv)
@app.route('/public/any/:port_pub/redirect/:ip_priv/:port_priv', method = 'PUT')
def create_public_redirection_p_ipp(port_pub, ip_priv, port_priv):
    # PUT {ip, port} (redirects ":ip_port" to "ip_priv:port_priv", the ipfloater will look for an IP)
    return create_public_redirection(None, port_pub, ip_priv, port_priv)
@app.route('/public/:ip_pub/redirect/:ip_priv/:port_priv', method = 'PUT')
def create_public_redirection_i_ipp(ip_pub, ip_priv, port_priv):
    # PUT {ip, port} (redirects "ip_pub:" to "ip_priv:port_priv", the ipfloater will look for an IP)
    return create_public_redirection(ip_pub, None, ip_priv, port_priv)
@app.route('/public/:ip_pub/redirect/:ip_priv', method = 'PUT')
def create_public_redirection_i_i(ip_pub, ip_priv):
    # PUT {ip, port} (redirects "ip_pub" to "ip_priv", the whole IP)
    return create_public_redirection(ip_pub, 0, ip_priv, 0)
@app.route('/public/redirect/:ip_priv/:port_priv', method = 'PUT')
def create_public_redirection_i_i(ip_priv, port_priv):
    # PUT {ip, port} (redirects to "ip_priv:port_priv", the ipfloater will look for an IP and a port)
    return create_public_redirection(None, None, ip_priv, port_priv)

@app.route('/public/:ip_pub/:port_pub', method = 'DELETE')
def delete_public_redirection(ip_pub, port_pub):
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")

    result = _ENDPOINT_MANAGER.terminate_endpoint_from(ip_pub, port_pub)
    if not result:
        return cpyutils.restutils.error(404, "Could not delete the redirection %s:%s. Does it exist?" % (ip_pub, port_pub))
    
    return cpyutils.restutils.response_txt("")

@app.route('/public/:ip_pub', method = 'DELETE')
def free_public_redirection(ip_pub):
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")

    if not _ENDPOINT_MANAGER.clean_public_ip(ip_pub):
        return cpyutils.restutils.error(404, "Could not clean the redirections from %s. Do they exist?" % (public_ip))
    
    return cpyutils.restutils.response_txt("")

@app.route('/private/')
def get_private_redirections():
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    return cpyutils.restutils.response_json(_ENDPOINT_MANAGER.get_endpoints_from_private(True))

@app.route('/private/:ip')
def get_private_redirections(ip):
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    eps = _ENDPOINT_MANAGER.get_endpoints_from_private(True)
    if ip in eps:
        return cpyutils.restutils.response_json(eps[ip])
    else:
        return cpyutils.restutils.error(404, "IP %s not found" % ip)

@app.route('/private/:ip/:port')
def get_public_redirections(ip, port):
    _ENDPOINT_MANAGER = ipfloaterd.get_endpoint_manager()
    if _ENDPOINT_MANAGER is None:
        return cpyutils.restutils.error(500, "Endpoint Manager not found")
    
    try:
        port = int(port.strip("/"))
    except:
        return cpyutils.restutils.error(400, "Malformed request: port is an integer")
    
    eps = _ENDPOINT_MANAGER.get_endpoints_from_private(True)
    if (ip in eps) and (port in (eps[ip])):
        return cpyutils.restutils.response_json((eps[ip])[port])
    else:
        return cpyutils.restutils.error(404, "redirection not found")
