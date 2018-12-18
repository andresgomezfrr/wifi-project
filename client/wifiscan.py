from scapy.all import *
#from kafka import KafkaClient, SimpleProducer
from datetime import datetime
from subprocess import call
import json
import time

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

#kafka = KafkaClient('192.168.1.104:9092')
#producer = SimpleProducer(kafka)

def packet_handler(pkt):
  if (pkt.haslayer(Dot11)):
    if (pkt.type == PROBE_REQUEST_TYPE and
        pkt.subtype == PROBE_REQUEST_SUBTYPE):
        process_packet(pkt)

def process_packet(pkt):
  json_string = packet_to_json(pkt)
  send_to_kafka(json_string)

def packet_to_json(pkt):
  packet_dict = dict()

  # RSSI Calcs
  try:
    extra = pkt.notdecoded
  except:
    extra = None

  if extra != None:
    signal_strength = -(256 - ord(extra[-4:-3]))
  else:
    signal_strength = -100

  # Dict values
  packet_dict['target'] = pkt.addr3
  packet_dict['src'] = pkt.addr2
  packet_dict['ssid'] = pkt.getlayer(Dot11ProbeReq).info
  packet_dict['rssi'] = signal_strength

  return json.dumps(packet_dict)

def send_to_kafka(string):
 # producer.send_messages('wireless', string)
  print string

def main():
  while True:
    print "[%s] Configuring interface monitor mode" % datetime.now()
    call(["ifconfig", sys.argv[1], "down"])
    call(["iwconfig", sys.argv[1], "mode", "monitor"])
    call(["ifconfig", sys.argv[1], "up"])
    print "[%s] Starting scan" % datetime.now()
    sniff(iface = sys.argv[1], prn = packet_handler, timeout=60)
    print "[%s] Stop scan" % datetime.now()  
    print "[%s] Configuring interface managed mode" % datetime.now()
    call(["ifconfig", sys.argv[1], "down"])
    call(["iwconfig", sys.argv[1], "mode", "managed"])
    call(["ifconfig", sys.argv[1], "up"])
    call(["route", "add", "default", "gw", sys.argv[2], sys.argv[1]])  
    time.sleep( 5 )

if __name__ == "__main__":
  main()
