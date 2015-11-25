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
import iptc
import logging
import cpyutils.log

_LOGGER = cpyutils.log.Log("IPT")

def delete_chain(table, chain_name):
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

def link_chains(table, first_chain, second_chain):
    '''
    This function executes an iptables rule that links the chain named "first_chain" to the chain named "second_chain"
    in table "table". At the end, it creates a rule like: iptables -t table.name -A FIRST_CHAIN -j SECOND_CHAIN
    '''
    rule = iptc.Rule()
    rule.target = rule.create_target(second_chain)
    chain = iptc.Chain(table, first_chain)
    chain.insert_rule(rule)
    
def unlink_chains(table, first_chain, second_chain):
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

def chain_exists(table, chain_name):
    '''
    This function returns true if the iptables chain named "chain_name" is in table "table"
    '''
    chains = [ chain.name for chain in table.chains if chain.name == chain_name ]
    if len(chains) > 0:
        return True
    else:
        return False

def remove_endpointchains(idendpoint):
    '''
    This method executes the needed funtions to remove the set of iptables rules that will make possible a redirection with the id in idendpoint.
    '''
    table = iptc.Table(iptc.Table.NAT)
    table.refresh()
    table.autocommit = False
    unlink_chains(table, "OUTPUT", "rule-%s-OUTPUT" % idendpoint)
    delete_chain(table, "rule-%s-OUTPUT" % idendpoint)

    unlink_chains(table, "POSTROUTING", "rule-%s-POSTROUTING" % idendpoint)
    delete_chain(table, "rule-%s-POSTROUTING" % idendpoint)

    unlink_chains(table, "PREROUTING", "rule-%s-PREROUTING" % idendpoint)
    delete_chain(table, "rule-%s-PREROUTING" % idendpoint)
    _LOGGER.debug("removing chain for endpoint %s" % idendpoint)
    table.commit()
    table.autocommit = True
    return True

def find_endpointchains_and_remove():
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
        remove_endpointchains(idendpoint)
