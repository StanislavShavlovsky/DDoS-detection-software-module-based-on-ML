import threading
import logging
import datetime
from scapy.all import sniff, TCP, UDP, IP
import os
from tabulate import tabulate

class DataStore:
    def __init__(self):
        self.__store = {}

    def write(self, event):
        ip = event['ip_addr_src']
        event.pop('ip_addr_src')
        if ip not in self.__store:
            self.__store[ip] = {'time_create': datetime.datetime.now(), 'events': []}
        self.__store[ip]['events'].append(event)

    def read_all(self):
        return self.__store

class Sniffer:
    def __init__(self, interface, store):
        self.__store = store
        self.interface = interface
        self.capture_thread = threading.Thread(target=self.__capture_packets)
        self.capture_thread.start()

    def __capture_packets(self):
        while True:
            try:
                packets = sniff(iface=self.interface, filter="ip", prn=self.__pkt_callback)
            except Exception as e:
                logging.error(f"Ошибка при захвате пакетов: {e}")

    def __pkt_callback(self, pkt):
        if IP in pkt:
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                event = {
                    "time": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f"),
                    "ip_addr_src": pkt[IP].src,
                    "ip_addr_dst": pkt[IP].dst,
                    "port_src": pkt.sport,
                    "port_dst": pkt.dport,
                    "transport_protocol_flag": str(pkt[TCP].flags.value) if TCP in pkt else "None"
                }
                self.__store.write(event)

class Analytics:
    def __init__(self, store):
        self.__store = store.read_all()
        self.__check()

    def __check(self):
        while True:
            for ip in list(self.__store.keys()):
                if len(self.__store[ip]['events']) >= 30:
                    self.__preprocessing(ip)
                    self.__store.pop(ip)

    def __preprocessing(self, ip):
        count_all_events = sum(len(entry['events']) for entry in self.__store.values())
        count_ip_events = len(self.__store[ip]['events'])
        ratio_count = count_ip_events / count_all_events
        ratio_udp = self.__take_count_flag_events(ip, 'None') / count_ip_events
        ratio_tcp = 1.0 - ratio_udp
        ratio_tcp_syn = self.__take_count_flag_events(ip, '2') / count_ip_events
        ratio_tcp_ack = self.__take_count_flag_events(ip, '16') / count_ip_events
        ratio_tcp_fin = self.__take_count_flag_events(ip, '1') / count_ip_events
        ratio_tcp_null = self.__take_count_flag_events(ip, '0') / count_ip_events
        ratio_tcp_xmas = self.__take_count_flag_events(ip, '41') / count_ip_events
        ratio_tcp_maimon = self.__take_count_flag_events(ip, '17') / count_ip_events
        ratio_tcp_other = 1.0 - ratio_tcp_syn - ratio_tcp_ack - ratio_tcp_fin - ratio_tcp_null - ratio_tcp_xmas - ratio_tcp_maimon - ratio_udp
        ratio_uniq_ports = len(set(entry['port_dst'] for entry in self.__store[ip]['events'])) / count_ip_events
        event_info = {
            "count": ratio_count,
            "tcp": ratio_tcp,
            "udp": ratio_udp,
            "tcp_syn": ratio_tcp_syn,
            "tcp_ack": ratio_tcp_ack,
            "tcp_fin": ratio_tcp_fin,
            "tcp_null": ratio_tcp_null,
            "tcp_xmas": ratio_tcp_xmas,
            "tcp_maimon": ratio_tcp_maimon,
            "tcp_other": ratio_tcp_other,
            "uniq_ports": ratio_uniq_ports
        }
        self.__print_result(ip, event_info)

    def __take_count_flag_events(self, ip, flag):
        return sum(1 for entry in self.__store[ip]['events'] if entry['transport_protocol_flag'] == flag)

    def __print_result(self, ip, event_info):
        headers = ["IP Адрес", "Количество событий", "TCP Отношение", "UDP Отношение", "TCP SYN Отношение", "TCP ACK Отношение",
                   "TCP FIN Отношение", "TCP NULL Отношение", "TCP XMAS Отношение", "TCP MAIMON Отношение", "TCP Другие Отношение",
                   "Уникальные порты Отношение"]
        data = [[ip, *event_info.values()]]
        print(tabulate(data, headers=headers, tablefmt="grid"))


# Создаем директорию для логов, если она не существует
log_dir = 'log'
os.makedirs(log_dir, exist_ok=True)


# Инициализация хранилища данных
data_store = DataStore()

try:
    # Запуск потоков Sniffer и Analytics
    sniffer = threading.Thread(name='sniffer', target=lambda: Sniffer("Realtek Gaming GbE Family Controller", data_store))
    analytics = threading.Thread(name='analytics', target=lambda: Analytics(data_store))
    sniffer.start()
    analytics.start()
except Exception as e:
    logging.error(f"Ошибка: {e}")
