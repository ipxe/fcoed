FCoE userspace test daemon
==========================

This trivial daemon provides control plane Fibre Channel over Ethernet
(FCoE) fabric services including a basic FIP responder and name
server.  It can be used to emulate the presence of a Fibre Channel
Forwarder (FCF) capable switch, in order to test fabric-mode FCoE
operations.

This software has absolutely zero robustness and absolutely cannot be
used in anything even remotely approaching a production environment.

Quick start
-----------

To create a trivial setup for testing against an FCoE target with
everything running on a local machine:

Create FCoE network interfaces:

```
sudo ip link add br-fcoe type bridge
sudo ip link set br-fcoe up
sudo ip link add fcoe1 address 02:fc:0e:00:00:01 type veth peer name vfcoe1
sudo ip link set fcoe1 up
sudo ip link set vfcoe1 up master br-fcoe
```

Build and run `fcoed` on the FCoE bridge interface:

```
make
sudo ./fcoed br-fcoe
```

Enable FCoE on the FCoE port:

```
sudo fcoeadm -c fcoe1
```

You should at this point see system log messages pertaining to the
registration of the FCoE port, e.g.:

```
fcoed: received FIP discovery from MAC 02:fc:0e:00:00:01 name 10:00:02:fc:0e:00:00:01
fcoed: added MAC 0e:fc:00:18:ae:01 (really 02:fc:0e:00:00:01) as port ID 18.ae.01
fcoed: FC GS PLOGI from ID 18.ae.01 PN 20:00:02:fc:0e:00:00:01
fcoed: FC NS register NN 10:00:02:fc:0e:00:00:01 for ID 18.ae.01
fcoed: FC NS register SNN "fcoe v0.1 over fcoe1" for NN 10:00:02:fc:0e:00:00:01
fcoed: FC NS register SPN "fcoe v0.1 over fcoe1" for ID 18.ae.01
```

Create an FCoE target:

```
sudo targetcli /tcm_fc create naa.200002fc0e000001
sudo targetcli /tcm_fc/naa.200002fc0e000001/luns create /backstores/<device>
sudo targetcli /tcm_fc/naa.200002fc0e000001/acls create naa.<port_id>
```
