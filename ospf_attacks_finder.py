import subprocess
import argparse
from collections import defaultdict
from typing import List, Dict


class TsharkRunner:
    """
    Runs Tshark commands and parses output.
    """

    @staticmethod
    def run_tshark(pcap_path: str, display_filter: str, fields: List[str]) -> List[Dict[str, str]]:
        """
        Run a Tshark command with the given display filter and extract fields.

        Args:
            pcap_path (str): Path to the pcap file.
            display_filter (str): Display filter for Tshark.
            fields (list): List of fields to extract.

        Returns:
            list: List of dictionaries, each containing extracted fields for a packet.
        """
        fields_str = " ".join(f"-e {field}" for field in fields)
        command = f"tshark -r \"{pcap_path}\" -Y \"{display_filter}\" -T fields {fields_str}"
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split("\n")
            parsed_data = [dict(zip(fields, line.split("\t"))) for line in lines if line]
            return parsed_data
        except subprocess.CalledProcessError as e:
            print(f"Error running Tshark: {e}")
            return []


class AnomalyDetector:
    """
    Base class for anomaly detectors.
    """

    def __init__(self, name: str):
        self.name = name

    def detect(self, packets: List[Dict[str, str]]) -> bool:
        """
        Analyze packets and detect anomalies.

        Args:
            packets (list): List of parsed packet data.

        Returns:
            bool: True if anomalies are detected, False otherwise.
        """
        raise NotImplementedError("This method must be implemented by subclasses.")


class DisguisedLSADetector(AnomalyDetector):
    """
    Detects Disguised LSA attacks and checks for the relevant fight-back packets.
    """

    def __init__(self):
        super().__init__("Disguised LSA Detector")

    def detect(self, packets: List[Dict[str, str]]) -> bool:
        anomalies_found = False

        for i in range(1, len(packets)):
            triggered_packet = packets[i - 1]
            disguised_packet = packets[i]

            # Check if the advertising router matches and sequence numbers differ by 1
            if (
                triggered_packet["ospf.advrouter"] == disguised_packet["ospf.advrouter"]
                and int(disguised_packet["ospf.lsa.seqnum"], 16) 
                - int(triggered_packet["ospf.lsa.seqnum"], 16) == 1
                and disguised_packet["ospf.advrouter"] != disguised_packet["ip.src"]
            ):
                
                # Check for fight-back packet as a response to the triggered packet
                fightback_packet = self._find_fightback_packet(packets[i + 1:], disguised_packet)
                
                if fightback_packet:
                    anomalies_found = True
                    victim_ip = disguised_packet["ospf.advrouter"]
                    attacker_ips = (triggered_packet["ip.src"], disguised_packet["ip.src"])
                    print(f"[+] Disguised LSA detected between frames {triggered_packet['frame.number']} and {disguised_packet['frame.number']}.")
                    print(f"    Attacker IPs: {attacker_ips}")
                    print(f"    Victim IP: {victim_ip}")
                    print(f"    Injected router: {fightback_packet['ip.dst']}")

                    # Print details of the desired packets
                    self._print_packet_details("Triggered Packet", triggered_packet)
                    self._print_packet_details("Disguised Packet", disguised_packet)
                    self._print_packet_details("Fight-back Packet", fightback_packet)

        return anomalies_found

    def _find_fightback_packet(self, subsequent_packets: List[Dict[str, str]], reference_packet: Dict[str, str]) -> Dict[str, str]:
        """
        Searches for a fight-back packet that matches the advertising router, sequence number, and checksum
        of the given reference packet in subsequent packets only.

        Args:
            subsequent_packets (list): Packets after the disguised packet.
            reference_packet (dict): The second packet in the sequence to compare against.

        Returns:
            dict: The matching fight-back packet, or None if no match is found.
        """
        for packet in subsequent_packets:
            # fight-back packet with the samr details of the disguised packet
            if (
                packet["ospf.advrouter"] == reference_packet["ospf.advrouter"]
                and packet["ospf.lsa.seqnum"] == reference_packet["ospf.lsa.seqnum"]
                and packet["ospf.lsa.chksum"] == reference_packet["ospf.lsa.chksum"]
                and packet["ospf.advrouter"] == packet["ip.src"]
            ):
                return packet
        return None

    def _print_packet_details(self, label: str, packet: Dict[str, str]):
        """
        Prints the details of a specific packet.

        Args:
            label (str): Label for the packet (e.g., Triggered Packet, Disguised Packet).
            packet (dict): The packet details to print.
        """
        print(f"\n    {label}:")
        print(f"        Frame: {packet['frame.number']}")
        print(f"        Sender: {packet['ip.src']}")
        print(f"        Advertising Router: {packet['ospf.advrouter']}")
        print(f"        Sequence Number: {packet['ospf.lsa.seqnum']}")
        print(f"        Checksum: {packet['ospf.lsa.chksum']}")

class RemoteFalseAdjacencyDetector(AnomalyDetector):
    """
    Detects Remote False Adjacency attacks.
    """

    def __init__(self):
        super().__init__("Remote False Adjacency Detector")

    def detect(self, packets: List[Dict[str, str]]) -> bool:
        anomalies_found = False

        for i in range(1, len(packets)):
            packet1 = packets[i - 1]
            packet2 = packets[i]

            # checks if I,M,MS flags turn on (Exstart state)
            if (
                "True" == packet1["ospf.dbd.i"] and "True" == packet2["ospf.dbd.i"] 
                and "True" == packet1["ospf.dbd.m"] and "True" == packet2["ospf.dbd.m"] 
                and "True" == packet1["ospf.dbd.ms"] and "True" == packet2["ospf.dbd.ms"]
            ):

                seq1 = int(packet1["ospf.db.dd_sequence"])
                seq2 = int(packet2["ospf.db.dd_sequence"])

                # Search for fake DBD packets from the phantom router
                if seq1 != seq2:
                    anomalies_found = True
                    print(f"[!] Sudden jump in sequence number - Potentially Remote False Adjacency attack detected.")
                    self._print_packet_details(packet1)
                    self._print_packet_details(packet2)
                    print(f"    The suspicious phantom router: {packet2['ip.src']}.")
                    print(f"    Check the OSPF neighbor session and the phantom router IP.")

        return anomalies_found

    @staticmethod
    def _print_packet_details(packet: Dict[str, str]):
        """
        Prints the details of a packet.

        Args:
            packet (dict): The packet data to print.
        """
        print(f"    Frame {packet['frame.number']}:")
        print(f"        Sender: {packet['ip.src']}")
        print(f"        DD Sequence: {packet['ospf.db.dd_sequence']}")
        print(f"        Flags:")
        print(f"            I: {packet['ospf.dbd.i']}")
        print(f"            M: {packet['ospf.dbd.m']}")
        print(f"            MS: {packet['ospf.dbd.ms']}")



class MismatchedFieldsDetector(AnomalyDetector):
    """
    Detects Mismatch Fields attacks.
    """

    def __init__(self):
        super().__init__("Mismatched Fields Detector")

    def detect(self, packets: List[Dict[str, str]]) -> bool:
        anomalies_found = False

        for packet in packets:
            if packet["ospf.lsa.id"] != packet["ospf.advrouter"] and packet["ospf.lsa"] == 1:
                anomalies_found = True
                print(f"[!] Mismatched Fields in Frame {packet['frame.number']}: "
                      f"Advertising Router: {packet['ospf.advrouter']} != Link State ID: {packet['ospf.lsa.id']}.")
        return anomalies_found


class AnomalyDetectionFramework:
    """
    Framework for running all registered anomaly detectors.
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.detectors = []

    def register_detector(self, detector: AnomalyDetector):
        """
        Register a new anomaly detector.

        Args:
            detector (AnomalyDetector): The detector to register.
        """
        self.detectors.append(detector)

    def run(self):
        """
        Run all registered detectors on the pcap file.
        """
        for detector in self.detectors:
            print(f"\n[+] Running {detector.name}...")
            packets = self.get_packets(detector)
            if not packets:
                print(f"[-] No relevant packets found for {detector.name}.")
                continue

            if not detector.detect(packets):
                print(f"[-] No anomalies detected by {detector.name}.")

    def get_packets(self, detector: AnomalyDetector) -> List[Dict[str, str]]:
        """
        Retrieve relevant packets for a specific detector.

        Args:
            detector (AnomalyDetector): The detector for which to retrieve packets.

        Returns:
            list: List of parsed packet data.
        """
        if isinstance(detector, DisguisedLSADetector):
            return TsharkRunner.run_tshark(
                self.pcap_path,
                "ospf.lsa.seqnum",
                ["frame.number", "ip.src", "ip.dst", "ospf.lsa.id", "ospf.advrouter", "ospf.lsa.seqnum", "ospf.lsa.chksum"]
            )
        elif isinstance(detector, RemoteFalseAdjacencyDetector):
            return TsharkRunner.run_tshark(
                self.pcap_path,
                "ospf.msg==2",
                ["frame.number", "ip.src", "ospf.dbd.i", "ospf.dbd.m", "ospf.dbd.ms", "ospf.db.dd_sequence"]
            )
        elif isinstance(detector, MismatchedFieldsDetector):
            return TsharkRunner.run_tshark(
                self.pcap_path,
                "ospf.lsa.id != ospf.advrouter",
                ["frame.number", "ospf.lsa.id", "ospf.advrouter", "ospf.lsa"]
            )
        return []


def main():

    parser = argparse.ArgumentParser(description="Detect OSPF anomalies in a pcap file.")
    parser.add_argument("-p", "--pcap_path", required=True, help="Path to the pcap file")
    args = parser.parse_args()

    framework = AnomalyDetectionFramework(args.pcap_path)
    framework.register_detector(DisguisedLSADetector())
    framework.register_detector(RemoteFalseAdjacencyDetector())
    framework.register_detector(MismatchedFieldsDetector())
    framework.run()

if __name__ == "__main__":
    main()
