Step 1: Setup and Installation
Start by install the requirements.txt
run this script
pip install -r requirements.txt
Ensure you have the necessary Python packages installed. If not, install them using pip:


pip install scapy pandas
Step 2: Understand the Code
The script provided captures network packets and saves the relevant details into a CSV file.

Imports: Import necessary libraries (scapy, pandas, and datetime).
Packet Processing Function: The process_packet function extracts details from each packet.
Packet List: packets_list stores the details of all captured packets.
Sniffing Packets: sniff function captures packets from the specified network interface.
DataFrame Creation: Converts the packet details list into a Pandas DataFrame.
CSV Saving: Saves the DataFrame to a CSV file (packets.csv).
Step 3: Adjust Network Interface
You need to specify the correct network interface for packet sniffing. On Windows, use Get-NetAdapter to find the interface name. On Linux, use ifconfig.

Step 4: Running the Script
Set the Network Interface:

Replace 'WiFi' with the actual interface name in your system.
Example for Windows: 'Ethernet', 'Wi-Fi', etc.
Example for Linux: 'eth0', 'wlan0', etc.
Run the Script:

Save the script as sniff_packets.py.
Open a terminal or command prompt and navigate to the directory containing the script.
Run the script using Python:
`python sniff_packets.py`