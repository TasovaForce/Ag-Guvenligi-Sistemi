from flask import Flask, render_template
from scapy.all import sniff, IP
from collections import Counter
from flask import jsonify
import pandas as pd
import threading


app = Flask(__name__)


@app.route('/update_data')
def update_data():
    traffic_count = Counter(traffic_data)
    top_ips = traffic_count.most_common(10)
    return jsonify(top_ips=top_ips, anomalies=anomalies)

# Global değişkenler
traffic_data = []
anomalies = []
threshold = 100  # Anomali tespiti için eşik değeri

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        traffic_data.append(src_ip)
        
        # Anomali tespiti
        if traffic_data.count(src_ip) > threshold:
            anomalies.append(src_ip)

def start_sniffing():
    sniff(prn=packet_callback, filter="ip", store=0)

@app.route('/')
def index():
    # Anlık raporlama
    traffic_count = Counter(traffic_data)
    top_ips = traffic_count.most_common(10)
    return render_template('index.html', top_ips=top_ips, anomalies=anomalies)

if __name__ == '__main__':
    # Ağ dinleme sürecini ayrı bir thread'de başlat
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True)
