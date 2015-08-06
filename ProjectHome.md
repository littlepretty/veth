# VETH #
## Virtual Ethernet tunnel driver for Linux 2.6 ##

This driver can connect remote ethernet device (ex. qemu virtual network interface)
```
   +-----------+          +---------------+
   |           |          |       QEMU(VM)|
   | eth   veth|          |          vnic |
   +--|------|-+          +--eth-------|--+
             |                         |
             +-------------------------+
```