The firewall should inspect all inbound packets and print to
file packets which match the rules that it receives in an
input. The firewall code is a user space implementation,
that reads packets from kernel queue, applies its pro-
cessing and then returns the packets back to the kernel
queue.

This is a user space implementation, that reads
inbound packets (sent from some host in the Internet to
the firewall host) from the kernel queue, applies its pro-
cessing and then sends the packets back to the kernel. To
retrieve the packets from the kernel queue, we use
 iptables firewall rules on the host on which 
run the implementation; 

The firewall implementation receives in an input an IP address ip, a port p, and a string ‘hello’, for instance: sudo ./cap ip p i hello Then it captures all incoming packets from the
kernel, and checks the source IP address and source port
– if they match the input values, then the implementation
checks if the input string appears in the payload
of that packet. The implementation prints to a file
out.txt payloadss of packets which match in the source
IP address and source port and contains in the payload
the input string, and the number of appearances of the
input string. 

The implementation should run on Linux kernel 3.6
(or more recent ones). 
The code uses a shell to set the firewall rule
when it is invoked and after printing i packets, before
terminating execution, the code deletes the firewall
rules.