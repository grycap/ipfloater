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
This is the last step, and you need to copy the file ```opennebula/ipfloater``` to the folder which contains the files for your VMM (i.e. ```/var/lib/one/remotes/vmm/kvm```) and add a piece of code to some files. If you are using KVM with ONE, you need to update the files ```/var/lib/one/remotes/vmm/kvm/attach_nic```, ```/var/lib/one/remotes/vmm/kvm/detach_nic```, ```/var/lib/one/remotes/vmm/kvm/shutdown``` and ```/var/lib/one/remotes/vmm/kvm/cancel```.

You can find a set of patch files that can be used to patch the files of OpenNebula 4.12.1 in folder ```opennebula/``` from the source code distribution of ```ipfloater```: ```attach_nic.patch```, ```cancel.patch```, ```detach_nic.patch``` and ```shutdown.patch```. All these files can be used with command ```patch```. An example is:

```bash
patch -p1 /var/lib/one/remotes/vmm/kvm/attach_nic < attach_nic.patch
patch -p1 /var/lib/one/remotes/vmm/kvm/detach_nic < detach_nic.patch
patch -p1 /var/lib/one/remotes/vmm/kvm/cancel < cancel.patch
patch -p1 /var/lib/one/remotes/vmm/kvm/shutdown < shutdown.patch
```

For the case of file ```/var/lib/one/remotes/vmm/kvm/attach_nic```, you just need to paste this piece of code just after the line ```NET_DRV=$5```.
This piece of code will check whether an IP that is assigned in the runtime is a floating IP or not. If it is not a floating IP, it will continue working as usual, but if it is a floating IP, this piece of code
will make the magic.

```bash
#-------- code snip to attach floating IPs --------------------------
source $(dirname $0)/ipfloater
attach_ip "$DOMAIN" "$MAC"
# -------------------------------------------------------------------
```

For the case of file ```/var/lib/one/remotes/vmm/kvm/detach_nic```, you just need to paste the following piece of code just after the line ```MAC=$2```.

```bash
#-------- code snip to attach floating IPs --------------------------
source $(dirname $0)/ipfloater
detach_ip "$DOMAIN" "$MAC"
# -------------------------------------------------------------------
```

Finally you MUST adjust the name of your gateway and ONE front-end, by using the variables IPFLOATER_HOST_REST, IPFLOATER_PORT_REST and ONE_FRONTEND in file ipfloater.

### ATTENTION: Distribute the files

Please make sure that the files that you modify in the VMM are distributed into the internal nodes. You can verify it by checking the contents of the corresponding ```/var/tmp/one/vmm``` folders in the internal nodes.

### Notes on IPFloater and ONE

As ONE keeps track of the IP leases, you can use an existing network in ONE. Then you will be able to get IPs from that ONE network either by using it for the VMs (i.e. getting the IP by using DHCP, cloud-init or statically configured addresses), or by using them in a floating-ip scheme by attaching them to the VMs.

### Using rOCCI server for ONE with floating IPs
You can enable floating IPs via rOCCI, using [rOCCI-server](https://github.com/EGI-FCTF/rOCCI-server). A common workflow is to create one VM and attaching a OCCI link to the VM, as it happens in the [EGI Federated Cloud aka FedCloud](http://www.egi.eu/infrastructure/cloud/). In order to use the rOCCI server, you just need to enable the floating IPs in ONE (as described above) and then adjust the file ```/etc/occi-server/backends/opennebula/templates/compute_nic.erb```

For the specific case of FedCloud, to get a public IP you should attach a compute to the ```/network/public``` network. Using the default installation, you cannot make it because of the template expects a network ID instead of a network name.

You can change it by modifying the file ```compute_nic.erb``` as follows:

```bash
NIC = [
  NETWORK = "<%= @networkinterface.target.split('/').last %>"
  ,NETWORK_UNAME = "oneadmin"
```

In FedCloud we have verified that it can be used in conjunction with rOCCI, just as it is done in OpenStack.