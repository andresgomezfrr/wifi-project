wifi-project
============

# Running wifiscan on Unix
The project depends on python (2.7 recommended) and scapy. You can install them with apt-get or yum.
You will also need a Zookeeper and Kafka installed on the system. Apache kafka from http://kafka.apache.org/downloads.html bundles a kafka broker and zookeeper server as an unique package.

1. Enable your Wifi device, but you should NOT be connected to a network

2. Enable monitor mode on your wifi device.
```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```
3. Run wifiscan.py as follows
```bash
sudo python wifiscan.py wlan0
```
4. Run a kafka consumer and ENJOY IT LEL. GG. EASY.
