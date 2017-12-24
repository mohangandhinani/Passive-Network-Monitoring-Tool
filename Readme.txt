Report

implemented a basic network monitoring tool that can capture from interface and also file
-> used getopt function to process the command line arguments
-> Automantically default interface will be choosen if no interface is provided
-> The program can both read from a interface or a pcap file
-> packets can be sampled using BPF expression and match string
-> for each packet got packet function will be called 
-> 1st level of handling is based on the ethernet type into ip packets and non ip packets
-> ip packets are again handled into tcp,udp,icmp and other packets
-> Data like time,source ,length of packet captured,destination MAC's and ip's,payload data are extracted from the packet. 

Compilation -
go to the directory containing mydump.c and run make command

Commands to run the code- 
(running as root sudo)
mydump [-i interface] [-r file] [-s string] expression

sudo ./mydump  -i wlp3s0 -s facebook (interface and string combination)
sudo ./mydump (captures indefinately on default interface)
sudo ./mydump   -r /home/mohan/Desktop/NetworkSecurity/hw1.pcap (read from pcap file)
./mydump   -r /home/mohan/Desktop/NetworkSecurity/hw1.pcap udp (bpf filter+ reading from file)


References -
http://www.tcpdump.org/sniffex.c
https://stackoverflow.com/questions/977684/how-can-i-express-10-milliseconds-using-timeval