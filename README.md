### Cisco AMP Device Flow Control (ampnetworkflow.ko)

Craig Davison <crdaviso@cisco.com>

### Description

This Linux kernel module monitors socket calls (send, recv, connect and accept)
made by userland processes.

### Supported kernels

This module has been tested on kernels 2.6.18 (as distributed in CentOS 5)
through 4.14 (as distributed in Amazon Linux 2). This module requires jprobes,
so kernel version 4.15 and higher are not currently supported.

### Build the module

Build the module by running make:

```
$ make
make -C /lib/modules/2.6.18-417.el5/build M=/home/crdaviso/ampnetworkflow EXTRA_CFLAGS="-I/home/crdaviso/ampnetworkflow/common/include " modules
make[1]: Entering directory `/usr/src/kernels/2.6.18-417.el5-x86_64'
  CC [M]  /home/crdaviso/ampnetworkflow/networkflow.o
  CC [M]  /home/crdaviso/ampnetworkflow/sockcallwatch_kprobe.o
  CC [M]  /home/crdaviso/ampnetworkflow/amp_skactg.o
  CC [M]  /home/crdaviso/ampnetworkflow/amp_addrcache.o
  CC [M]  /home/crdaviso/ampnetworkflow/common/src/amp_log.o
  LD [M]  /home/crdaviso/ampnetworkflow/ampnetworkflow.o
  Building modules, stage 2.
  MODPOST
  CC      /home/crdaviso/ampnetworkflow/ampnetworkflow.mod.o
  LD [M]  /home/crdaviso/ampnetworkflow/ampnetworkflow.ko
make[1]: Leaving directory `/usr/src/kernels/2.6.18-417.el5-x86_64'
```

To build the module with verbose logging support, run
`make EXTRA_CFLAGS=-DAMP_DEBUG`.

### Build the test client

Build the test client in the test_client directory
(requires libmnl - http://www.netfilter.org/projects/libmnl/):

```
$ cd test_client
$ make
cc -o test_client test_client.c -Wall -Wextra -g -lmnl
```

### Run the test client

Run the test client as root. Sample output for a wget session:

```
$ sudo ./test_client
genl ctrl msg
Family ID: 22
amp msg
SK_OP SEND pid 15455 uid 500 filename /usr/bin/wget local_addr 172.16.231.199:49526 remote_addr 172.16.231.2:53 proto 17 sock_id 72398988640257
amp msg
SK_OP RELEASE pid 15455 uid 500 filename /usr/bin/wget local_addr 172.16.231.199:49526 proto 17 sock_id 72398988640257
amp msg
SK_OP SEND pid 15455 uid 500 filename /usr/bin/wget local_addr 172.16.231.199:56547 remote_addr 172.16.231.2:53 proto 17 sock_id 72398988640258
amp msg
SK_OP RELEASE pid 15455 uid 500 filename /usr/bin/wget local_addr 172.16.231.199:56547 proto 17 sock_id 72398988640258
amp msg
SK_OP CONNECT pid 15455 uid 500 filename /usr/bin/wget local_addr 0.0.0.0:0 remote_addr 173.37.145.84:80 proto 6 sock_id 72398988640259
amp msg
SK_OP SEND pid 15455 uid 500 filename /usr/bin/wget local_addr 172.16.231.199:32965 remote_addr 173.37.145.84:80 proto 6 sock_id 72398988640259 payload [GET / HTTP/1.0..User-Agent: Wget/1.11.4 Red Hat modified..Accept: */*..Host: www.cisco.com..Connection: Keep-Alive....] payload_seqnum 0
amp msg
SK_OP RELEASE pid 15455 uid 500 local_addr 172.16.231.199:32965 remote_addr 173.37.145.84:80 proto 6 sock_id 72398988640259
```

