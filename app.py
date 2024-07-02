import streamlit as st
import pandas as pd
import scapy.all as scapy
import threading
import time

# Define a global dataframe to store captured packet data
captured_data = pd.DataFrame(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'size', 'timestamp'])

def packet_callback(packet):
    global captured_data
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        features = {
            'src_ip': packet[scapy.IP].src,
            'dst_ip': packet[scapy.IP].dst,
            'src_port': packet[scapy.TCP].sport,
            'dst_port': packet[scapy.TCP].dport,
            'size': len(packet),
            'timestamp': packet.time,
        }
        captured_data = captured_data.append(features, ignore_index=True)

def continuous_capture(interface, filter, count=10):
    scapy.sniff(iface=interface, filter=filter, prn=packet_callback, count=count)

st.title('Real-Time Network Traffic Capture and Analysis for Website')

interface = st.text_input('Network Interface', value='eth0')
website_ip = st.text_input('Website IP Address', value='93.184.216.34')
packet_count = st.number_input('Number of Packets to Capture per Batch', min_value=1, max_value=1000, value=10)

if st.button('Start Real-Time Capture'):
    filter = f'host {website_ip} and (tcp port 80 or tcp port 443)'
    capture_thread = threading.Thread(target=continuous_capture, args=(interface, filter, packet_count))
    capture_thread.start()

    placeholder = st.empty()
    while True:
        with placeholder.container():
            st.write("Captured Data")
            st.dataframe(captured_data)
        time.sleep(1)  # Adjust the sleep time as needed