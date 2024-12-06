import subprocess
import argparse

def ospf_packets_filter(pcap_path):
    command = f"tshark -r \"{pcap_path}\" -Y \"ospf.lsa.seqnum\" -T fields -e frame.number -e ip.src -e ospf.lsa.id -e ospf.advrouter -e ospf.lsa.seqnum -e ospf.checksum"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        return result.stdout.splitlines()
    else:
        print("Tshark command failed.")
        return []
    
def process_packets(packets):

    packet_data = []
    for packet in packets:
        fields = packet.split('\t')
        if len(fields) == 6:
            frame_number = fields[0]
            source_ip = fields[1]
            linkstate_id = fields[2]
            advertising_router = fields[3]
            sequence_number = fields[4]
            checksum = fields[5]
            packet_data.append((frame_number, source_ip, linkstate_id, advertising_router, sequence_number, checksum))
    
    for i in range(1, len(packet_data)):
        first_frame_number, first_source_ip, first_linkstate_id, first_advertising_router, first_sequence_number, first_checksum = packet_data[i-1]
        second_frame_number, second_source_ip, second_linkstate_id, second_advertising_router, second_sequence_number, second_checksum = packet_data[i]
        print(first_sequence_number)
        if first_advertising_router == second_advertising_router and abs(int(first_sequence_number, 16) - int(second_sequence_number, 16)) == 1:
            print(f"[+] Found potential disguised LSA attack between frames {first_frame_number} and {second_frame_number}.")

            fightback_frame = None
            for j in range(i+1, len(packet_data)):
                fightback_frame_number, fightback_source_ip, fightback_linkstate_id, fightback_advertising_router, fightback_sequence_number, fightback_checksum = packet_data[j]
                if second_advertising_router == fightback_advertising_router and second_sequence_number == fightback_sequence_number and second_checksum == fightback_checksum:
                    fightback_frame = (fightback_frame_number, fightback_source_ip, fightback_linkstate_id, fightback_advertising_router, fightback_sequence_number, fightback_checksum)
                    break

            if fightback_frame:
                attacker_ips = (first_source_ip, second_source_ip)
                victim_ip = first_advertising_router
                print(f"\n[!] Disguised LSA OSPF Attack Detected.")
                print(f"        Attacker IPs: {attacker_ips}")
                print(f"        Victim IP: {victim_ip}")
                print(f"    \n        Triggered OSPF Frame: {first_frame_number}")
                print(f"                 Sender: {first_source_ip}")
                print(f"                 Advertising Router: {first_advertising_router}")
                print(f"                 Sequence Number: {first_sequence_number}")
                print(f"                 Checksum: {first_checksum}")
                print(f"    \n        Disguised OSPF Frame: {second_frame_number}")
                print(f"                 Sender: {second_source_ip}")
                print(f"                 Advertising Router: {second_advertising_router}")
                print(f"                 Sequence Number: {second_sequence_number}")
                print(f"                 Checksum: {second_checksum}")
                print(f"    \n        OSPF Fight-back Mechanism in Frame: {fightback_frame[0]}")
                print(f"                 Advertising Router: {fightback_frame[3]}")
                print(f"                 Sequence Number: {fightback_frame[4]}")
                print(f"                 Checksum: {fightback_frame[5]}\n")
            else:
                if first_linkstate_id != first_advertising_router:
                    print("Bypass of the fight-back mechanism detected.")
                else:
                    print("[-] No fight-back frame found. Attack not fully confirmed.")
        if first_advertising_router != first_linkstate_id:
            print(f"[+] Found potential Mismatched Fields Attack between frames - Adversiting Router {first_advertising_router} does not match to Link State ID {first_linkstate_id}.")
       
def main():

    parser = argparse.ArgumentParser(description="Detect disguised LSA attack in a pcap file.")
    parser.add_argument("-p", "--pcap_path", required=True, help="Path to the pcap file")
    args = parser.parse_args()

    ospf_packets = ospf_packets_filter(args.pcap_path)

    if ospf_packets:
        process_packets(ospf_packets)

if __name__ == '__main__':
    main()

