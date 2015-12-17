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
import cpyutils.config

cpyutils.config.set_paths([ './etc/', '/etc/default/', '/etc/ipfloater/', '/etc/' ])
cpyutils.config.set_main_config_file("ipfloaterd.conf")

class IPFloaterConfig(cpyutils.config.Configuration):
    def parse(self):
        self.IP_POOL = cpyutils.config.Configuration.str2list(self.IP_POOL)
        self.PRIVATE_IP_RANGES = cpyutils.config.Configuration.str2list(self.PRIVATE_IP_RANGES)

config = IPFloaterConfig(
    "IPFLOATER",
    {
        "IP_POOL": "",
        "IP_POOL_FILE": "",
        "LISTEN_IP": "127.0.0.1",
        "LISTEN_PORT": 7000,
        "REST_IP": "127.0.0.1",
        "REST_PORT": 7002,
        "REMOVE_AT_BOOT": True,
        "DB": "sqlite:///var/lib/ipfloater/ipfloater.db",
        "PRIVATE_IP_RANGES": "",
        "BLOCK_PUBLIC_IPS": True
    },
    callback = IPFloaterConfig.parse
)
