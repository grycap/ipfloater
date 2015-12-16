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
import cpyutils.log
import cpyutils.iputils

_LOGGER=cpyutils.log.Log()

def read_csv(filename, separator = " ", clean_callback = None, min_expected_fields = None, max_expected_fields = None):
    accepted = []
    ignored = []
    try:
        for line in open(filename):
            # Remove comments
            line = line.split('#',1)[0]
            line = line.strip()
            if line != "":
                # line = line.replace("\t"," ")
                if clean_callback is not None:
                    line = clean_callback(line)
                    
                line_split = [ line ]
                
                # Allow multiple separators
                for s in separator:
                    result = []
                    for l in line_split:
                        splitted = l.split(s)
                        if len(splitted) > 1:
                            result = result + splitted
                        else:
                            result.append(l)
                    line_split = result
                    
                # The problem of this is that it does not allow blank fields
                lineparts = [ x.strip() for x in line_split ]
                if min_expected_fields is not None:
                    if len(lineparts) < min_expected_fields:
                        _LOGGER.warning("malformed CSV entry: few values")
                        ignored.append(lineparts)
                        continue
                    
                if max_expected_fields is not None:
                    if len(lineparts) > max_expected_fields:
                        _LOGGER.warning("malformed CSV entry: too values")
                        ignored.append(lineparts)
                        continue

                accepted.append(lineparts)
    except IOError, e:
        _LOGGER.error("cannot read entries for file %s" % filename)
        raise e
        
    return accepted, ignored

class ARPTable(object):    
    def get_ip(self, mac):
        '''
        Returns the IP associated to the provided MAC (or None if fails or does not exist)
        '''
        check_mac = cpyutils.iputils.check_mac(mac)
        if check_mac is None:
            _LOGGER.error("malformed mac %s query" % mac)
            return None
        if check_mac in self.mac2ip:
            return self.mac2ip[check_mac]
        return None
    
    def get_mac(self, ip):
        '''
        Returns the MAC associated to the provided IP (or None if fails or does not exist)
        '''
        check_ip = cpyutils.iputils.check_ip(ip)
        if check_ip is None:
            _LOGGER.error("malformed ip %s query" % ip)
            return None
        if check_ip in self.ip2mac:
            return self.ip2mac[check_ip]
        return None

    def del_entry(self, orig_ip, orig_mac):
        '''
        Deletes an existing entry from the resolution table
        * checks (and fails) in case of non existance, and also checks the format for the IP and the MAC addresses
        '''
        mac = cpyutils.iputils.check_mac(orig_mac)
        ip = cpyutils.iputils.check_ip(orig_ip)
        if mac is None:
            _LOGGER.error("malformed mac (%s)" % mac)
            return False
        if ip is None:
            _LOGGER.error("malformed ip (%s)" % ip)
            return False
        if mac not in self.mac2ip:
            _LOGGER.error("tried to delete a mac that is not managed by us (%s)" % orig_mac)
            return False
        if ip not in self.ip2mac:
            _LOGGER.error("tried to delete an ip that is not managed by us (%s)" % orig_ip)
            return False
        del self.ip2mac[ip]
        del self.mac2ip[mac]
        return True
    
    def del_ip(self, orig_ip):
        '''
        Deletes an existing entry from the resolution table using only the IP
        * checks (and fails) in case of non existance, and also checks the format for the IP address
        '''
        ip = cpyutils.iputils.check_ip(orig_ip)
        if ip is None:
            _LOGGER.error("malformed ip (%s)" % ip)
            return False

        if ip in self.ipwithoutmac:
            del self.ipwithoutmac[ip]
            return True
        
        if ip not in self.ip2mac:
            _LOGGER.error("tried to delete an ip that is not managed by us (%s)" % orig_ip)
            return False

        mac = self.ip2mac[ip]
        del self.ip2mac[ip]
        del self.mac2ip[mac]
        return True

    def del_mac(self, orig_mac):
        '''
        Deletes an existing entry from the resolution table using only the MAC
        * checks (and fails) in case of non existance, and also checks the format for the MAC address
        '''
        mac = cpyutils.iputils.check_mac(orig_mac)
        if mac is None:
            _LOGGER.error("malformed mac (%s)" % mac)
            return False
        if mac not in self.mac2ip:
            _LOGGER.error("tried to delete a mac that is not managed by us (%s)" % orig_mac)
            return False
        
        ip = self.mac2ip[mac]
        del self.ip2mac[ip]
        del self.mac2ip[mac]
        return True
    
    def add_ip_without_mac(self, orig_ip):
        '''
        Adds a new ip to the ip without mac structure... just for the case of known ips where the mac is unknown
        * checks (and fails) in case of duplicates, and also checks the format for the IP address
        '''
        ip = cpyutils.iputils.check_ip(orig_ip)
        if ip is None:
            _LOGGER.error("malformed ip (%s)" % orig_ip)
            return False
        if ip in self.ip2mac or ip in self.ipwithoutmac:
            _LOGGER.error("duplicated ip %s" % (ip))
            return False
        self.ipwithoutmac[ip] = "000000000000"
        return True
    
    def add_entry(self, orig_ip, orig_mac):
        '''
        Adds a new entry to the resolution table
        * checks (and fails) in case of duplicates, and also checks the format for the IP and the MAC addresses
        '''
        mac = cpyutils.iputils.check_mac(orig_mac)
        ip = cpyutils.iputils.check_ip(orig_ip)
        if mac is None:
            _LOGGER.error("malformed mac (%s)" % orig_mac)
            return False
        if ip is None:
            _LOGGER.error("malformed ip (%s)" % orig_ip)
            return False
        if ip in self.ip2mac:
            _LOGGER.error("duplicated ip %s (ignoring mac %s)" % (ip, orig_mac))
            return False
        if mac in self.mac2ip:
            _LOGGER.error("duplicated mac %s (ignoring ip %s)" % (mac, orig_ip))
            return False
        if ip in self.ipwithoutmac:
            _LOGGER.debug("the mac for the ip %s was unknown, and now it is known (%s)" % (ip, orig_mac))
            del self.ipwithoutmac[ip]
            
        self.mac2ip[mac] = ip
        self.ip2mac[ip] = mac
        return True
    
    def length(self):
        '''
        Returns the number of entries in the table
        '''
        return len(self.mac2ip)
    
    def get_ips(self):
        '''
        Returns the list of ips contained in the arp table
        '''
        return self.ip2mac.keys()
    
    def get_ips_without_mac(self):
        '''
        Returns the list of ips for which we do not know the mac address
        '''
        return self.ipwithoutmac.keys()

    def get_macs(self):
        '''
        Returns the list of macs contained in the arp table
        '''
        return self.mac2ip.keys()
    
    def clean_line(self, line):
        '''
        Cleans the line that is read from the file (removes multiple blank spaces)
        '''
        line = line.replace("\t", " ")
        cleaned = line.replace("  ", " ")
        while cleaned != line:
            line = cleaned
            cleaned = line.replace("  ", " ")
        return line
    
    def read_from_file(self, filename):
        '''
        Reads a file in which pairs of MAC IP are expected, separated by blank spaces (or tabs). It allows comments.
        * If the file does not exist, it return None.
        * Otherwise it returns the number of entries that were ignored.
        * If there are not any ignored entries, it will return 0
        '''
        try:
            entries, ignored = read_csv(filename, ' ', self.clean_line)
        except:
            _LOGGER.error("an error occurred when trying to entries from file %s" % filename)
            return None
        for entry in entries:
            if len(entry) > 1:
                self.add_entry(entry[0], entry[1])
            else:
                self.add_ip_without_mac(entry[0])
        ignored_count = len(ignored)
        _LOGGER.debug("added %s entries" % len(entries))
        if ignored_count > 0:
            _LOGGER.warning("%d entries were ignored" % ignored_count)
            return -ignored_count
        return 0
    
    def __init__(self):
        self.mac2ip = {}
        self.ip2mac = {}
        self.ipwithoutmac = {}