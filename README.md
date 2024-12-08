# OSPF_Attacks_Finder

After reading Gabi Nakibly, Alex Kirshon, and Dima Gonikman's research on OSPF attacks, I realized the power, impact, and relevance of L3 attacks, in particular related to OSPF. OSPF is the most used routing protocol in small and large networks today. 

The OSPF Attacks Finder is a command line tool that detects OSPF attacks in a given pcap file.  The tool is designed for security researchers and network administrators to check if there is routing poisoning in their network. The tool finds the potential for the following attacks:
        
Disguised LSA
Mismatched field attacks 
Remote False Adjacency 

It is done by Tshark filtering and Python parsing. The tool is built in a framework format and allows for easy addition of new analyses.

### Usage
CMD:
```cmd
python ospf_attacks_finder.py -p <your_pcap>
```

Example Output:
```cmd
[+] Disguised LSA detected between frames 88 and 89.
        Attacker IPs: ('192.168.118.25', '192.168.84.90')
        Victim IP: 192.168.75.11
        Injected router: 192.168.75.201

        Triggered Packet: 
                Frame: 88
                 Sender: 192.168.118.25
                 Advertising Router: 192.168.75.11
                 Sequence Number: 0x80000055
                 Checksum: 0x2cc8

        Disguised Packet
                 Frame: 89
                 Sender: 192.168.84.90
                 Advertising Router: 192.168.75.11
                 Sequence Number: 0x80000056
                 Checksum: 0x417b

        Fight-back Packet:
                 Frame: 90
                 Sender: 192.168.75.11
                 Advertising Router: 192.168.75.11
                 Sequence Number: 0x80000056
                 Checksum: 0x417b
```

### Add Your Anlysis
1. Add your analysis class that will inherit from AnomalyDetector.
2. Implement the init and detect function to your class (The analysis commited in detect function).
3. In get_packets function of AnomalyDetectionFramework add your class (There you also send the output and fields to the tshark query).
4. In main, use the register_detector method of 'framwork' instance and pass to it your analysis class.
5. Enjoy!

