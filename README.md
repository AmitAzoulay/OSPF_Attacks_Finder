# OSPF_Attacks_Finder

After reading Gabi Nakibly, Alex Kirshon, and Dima Gonikman's research on OSPF attacks, I realized the power, impact, and relevance of L3 attacks, in particular related to OSPF. OSPF is the most used routing protocol in small and large networks today. 

The OSPF Attacks Finder is a command line tool that detects OSPF attacks in a given pcap file.  The tool is designed for security researchers and network administrators to check if there is routing poisoning in their network. The tool finds disguised LSA and Mismatched field attacks by Tshark filtering and Python parsing.

CMD:
```cmd
python ospf_attacks_finder.py -p <your_pcap>
```

Example Output:
```cmd
[+] Found potential disguised LSA attack between frames 88 and 89.

[!] Disguised LSA OSPF Attack Detected.
        Attacker IPs: ('192.168.118.25', '192.168.84.90')
        Victim IP: 192.168.75.11

        Triggered OSPF Frame: 88
                 Sender: 192.168.118.25
                 Advertising Router: 192.168.75.11
                 Sequence Number: 0x80000055
                 Checksum: 0x2cc8

        Disguised OSPF Frame: 89
                 Sender: 192.168.84.90
                 Advertising Router: 192.168.75.11
                 Sequence Number: 0x80000056
                 Checksum: 0x417b

        OSPF Fight-back Mechanism in Frame: 101
                 Advertising Router: 192.168.75.11
                 Sequence Number: 0x80000056
                 Checksum: 0x417b

[+] Found potential disguised LSA attack between frames 104 and 105.
[-] No fight-back frame found. Attack not fully confirmed.
```
