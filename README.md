# OSPF_Attacks_Finder

After reading Gabi Nakibly, Alex Kirshon, and Dima Gonikman's research on OSPF attacks, I realized the power, impact, and relevance of L3 attacks, in particular related to OSPF. OSPF is the most used routing protocol in small and large networks today. 

The OSPF Attacks Finder is a command line tool that detects OSPF attacks in a given pcap file.  The tool is designed for security researchers and network administrators to check if there is routing poisoning in their network. The tool finds disguised LSA and Mismatched Fields Attacks.

CMD:
```cmd
python ospf_attacks_finder.py -p <your_pcap>
```
