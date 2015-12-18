# Floating IPs in OpenNebula
This documents explains how to implement [Amazon AWS](https://aws.amazon.com)-like and [OpenStack](https://www.openstack.org/)-like floating IPs in [OpenNebula](http://opennebula.org/), using [IPFloater](https://github.com/grycap/ipfloater).

## Why floating IPs?
Public IPs are "expensive", while private IPs are "cheap". That means that, while you can create a lot of private IPs to connect your VMs, there usually are a few publicly addressable IPs available. So you must take care of
how you use these public IPs.
In the case of having a deployment that consists of a publicly IP addressable VM
and a set of VMs that connect to the the former one via a private IP, you do not need a public IP for each of the VMs. You would need just only one public IP for the main VM.
This is the case of a cluster of VMs, where one of them act as the front-end and the other are working nodes that do not need (and probably should not be)
accessed from the outside world.

At the end, when you create a VM in OpenNebula (ONE) in your premises, you do not know whether it needs a publicly addressable network or not. Using floating IPs, you could create the VM
using cheap private IPs and later, in runtime, you can assign a public IP to that VM, to connect from the outside world.

This is just how Amazon AWS and OpenStack work. When you access via ssh to the VM, you can find a private IP, while you are using a publicly addressable IP.

## How it works?
ONE has implemented a mechanism called "attach nic" that will make that in your VM appear a new NIC interface that could have a public IP in the runtime. But in that case, you need to configure the VM (i.e. create new entries
for the interface, or using the console issuing weird commands such as ```ifconfig``` or ```ip link```).

Using this mechanism, if you attach a nic that is part of a floating ip pool, you will automatically have access to the VM via the publicly addressable IP that has been assigned to the VM by ONE.

## How can it be done in ONE?
First of all, you can install ipfloater in the host that is routing the private IPs to privide internet access to the VMs (i.e. the gateway of the private network).
Then you should get a pool of publicly addressable IPs, along with their MAC addresses (if they are not statically assigned, you can invent them with the proper form: e.g. 60:60:00:00:00:01).

And now you have to prepare the IPFloater and ONE:

### Known issues
First of all it is important to state that there is a problem (it will be solved soon), because when the VM is deleted or shutdown, the attached nics are not detached from the VM. So it is needed some extra code when finalising a VM. Also it is needed to check what happens when saving, migrating and powering off VMs.

### Preparing IPFloater.
You need to assign the public IPs to the IPFloater. You can make this by creating a file like this and use it ```IP_POOL_FILE``` in the configuration of IPFloater:

```bash
216.58.211.227  60:00:00:00:00:01
216.58.211.228  60:00:00:00:00:01
```

Then you need to assign these IPs to the main interface of your gateway (probably eth0). You can make it by issuing the following commands:

```bash
ip addr add 216.58.211.227 dev eth0
ip addr add 216.58.211.228 dev eth0
```

And finally, you can start IPFloater. You can verify that IPFloater is properly working by checking the iptables:

```bash
iptables -t nat -S | grep ipfl
```

You should find these lines:

```bash
-N ipfloater-OUTPUT
-N ipfloater-POSTROUTING
-N ipfloater-PREROUTING
-A PREROUTING -j ipfloater-PREROUTING
-A OUTPUT -j ipfloater-OUTPUT
-A POSTROUTING -j ipfloater-POSTROUTING
-A ipfloater-POSTROUTING -m conntrack ! --ctstate DNAT -j ACCEPT
```

### Preparing ONE

Now you have to create the network that contains the pairs IP-MAC address in ONE. Let's call it ```floating-ips```.

```bash
cat > floating-ips.net << EOF
NAME=floating-ips
BRIDGE=br0
AR=[TYPE = "IP4", IP = "216.58.211.227", MAC = "60:60:00:00:00:01", SIZE = "1" ]
AR=[TYPE = "IP4", IP = "216.58.211.228", MAC = "60:60:00:00:00:02", SIZE = "1" ]
EOF
onevnet create floating-ips.net
```

If you want to be able to use it as a common network (being able of use it by assigning it to a VM), you should probably pay attention to the parameter ```BRIDGE``` and also include other parameters.

### Preparing the ONE VMM
This is the last step, and you need to add a piece of code to your favourite VMM. If you are using KVM with ONE, you need to update the files ```/var/lib/one/remotes/vmm/kvm/attach_nic``` and ```/var/lib/one/remotes/vmm/kvm/detach_nic```.


For the case of file ```/var/lib/one/remotes/vmm/kvm/attach_nic```, you just need to paste this piece of code just after the line ```NET_DRV=$5```.
This piece of code will check whether an IP that is assigned in the runtime is a floating IP or not. If it is not a floating IP, it will continue working as usual, but if it is a floating IP, this piece of code
will make the magic.

```bash
#-------- code snip to attach floating IPs --------------------------
IPFLOATER_HOST_REST=onecloud
IPFLOATER_PORT_REST=7003
ONE_FRONTEND=onecloud
#-------- end of configuration --------------------------------------
IPFLOATER_REST_SERVER=$IPFLOATER_HOST_REST:$IPFLOATER_PORT_REST
VMID=${DOMAIN:4}
FLOATING_IP=$(curl -fXGET http://$IPFLOATER_REST_SERVER/arp/$MAC)
if [ $? -eq 0 ] && [ "$FLOATING_IP" != "" ]; then
        IP=$(ssh $ONE_FRONTEND "onevm show $VMID -x | /var/lib/one/remotes/datastore/xpath.rb /VM/TEMPLATE/NIC[NIC_ID=0]/IP | head -n 1")
        if [ "$IP" != "" ]; then
                RESULT=$(curl -fXPUT http://$IPFLOATER_REST_SERVER/public/$FLOATING_IP/redirect/$IP)
                if [ $? -ne 0 ]; then
                        log_error "could not attach floating IP $FLOATING_IP to $IP ($RESULT)"
                        exit 1
                fi
                log_info "IP $FLOATING_IP successfully attached to ip $IP"
                exit 0
        else
                log_error "requesting a floating IP but could not get the main IP of vm $DOMAIN"
                exit 1
        fi
fi
# -------------------------------------------------------------------
```

For the case of file ```/var/lib/one/remotes/vmm/kvm/detach_nic```, you just need to paste the following piece of code just after the line ```MAC=$2```.

```bash
#-------- code snip to attach floating IPs --------------------------
IPFLOATER_HOST_REST=onecloud
IPFLOATER_PORT_REST=7003
ONE_FRONTEND=onecloud
#-------- end of configuration --------------------------------------
IPFLOATER_REST_SERVER=$IPFLOATER_HOST_REST:$IPFLOATER_PORT_REST
VMID=${DOMAIN:4}
FLOATING_IP=$(curl -fXGET http://$IPFLOATER_REST_SERVER/arp/$MAC)
if [ $? -eq 0 ] && [ "$FLOATING_IP" != "" ]; then
        IP=$(ssh $ONE_FRONTEND "onevm show $VMID -x | /var/lib/one/remotes/datastore/xpath.rb /VM/TEMPLATE/NIC[NIC_ID=0]/IP | head -n 1")
        if [ "$IP" != "" ]; then
                RESULT=$(curl -fXDELETE http://$IPFLOATER_REST_SERVER/public/$FLOATING_IP/redirect/$IP)
                if [ $? -ne 0 ]; then
                        log_error "could not detach floating IP $FLOATING_IP to $IP ($RESULT)"
                        exit 1
                fi
                log_info "IP $FLOATING_IP successfully detached from ip $IP"
                exit 0
        else
                log_error "detaching a floating IP but could not get the main IP of vm $DOMAIN"
                exit 1
        fi
fi
# -------------------------------------------------------------------
```

In both cases you must adjust the names of your gateway and ONE front-end, by using the variables IPFLOATER_HOST_REST, IPFLOATER_PORT_REST and ONE_FRONTEND
