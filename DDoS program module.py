import tkinter as tk  # Импортируем модуль для создания графического интерфейса
from tkinter import ttk  # Импортируем ttk для улучшения стиля виджетов
from tkinter import messagebox, filedialog  # Импортируем модули для диалоговых окон
import threading  # Импортируем threading для работы с многопоточностью
import logging  # Импортируем logging для ведения журнала
import datetime  # Импортируем datetime для работы с датой и временем
import os  # Импортируем os для работы с операционной системой
import pickle  # Импортируем pickle для сериализации объектов
import time  # Импортируем time для работы со временем
import pandas as pd  # Импортируем pandas для работы с данными в формате таблицы
import ipaddress  # Импортируем ipaddress для работы с IP-адресами
import socket  # Импортируем socket для работы с сокетами
from collections import defaultdict  # Импортируем defaultdict для работы с данными по умолчанию
from sklearn.model_selection import train_test_split  # Импортируем train_test_split для разделения данных на обучающие и тестовые
from sklearn.ensemble import RandomForestClassifier  # Импортируем RandomForestClassifier для обучения модели случайного леса
from scapy.layers.inet import IP  # Импортируем IP из scapy для работы с пакетами IP
from scapy.layers.l2 import Ether  # Импортируем Ether из scapy для работы с пакетами Ethernet
from sklearn.preprocessing import LabelEncoder  # Импортируем LabelEncoder для кодирования категориальных признаков
import subprocess  # Импортируем subprocess для выполнения внешних команд
import csv  # Импортируем csv для работы с файлами CSV
import socket


# Класс для хранения данных о сетевом трафике
class DataStore:
    def __init__(self):
        self.store = dict()

    # Метод для записи данных события в хранилище
    def write(self, event):
        ip = event['ip_addr_src']
        if ip not in self.store:
            self.store[ip] = {'time_create': datetime.datetime.now(), 'total_fwd_packets': 0}
        self.store[ip]['total_fwd_packets'] += 1

    # Метод для чтения всех данных из хранилища
    def read_all(self):
        return self.store


# Функция для мониторинга сетевого трафика
def monitor_traffic(iface, text_widget):
    # Настройки мониторинга трафика
    base_traffic_rate = 1000
    ip_threshold = 100
    attack_packet_types = ["SYN", "UDP"]
    traffic_interval = 1
    ip_counts = defaultdict(int)

    start_time = time.time()
    packets_received = 0

    # Установка сокета для прослушивания сетевого интерфейса
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
        sock.bind((iface, 0))
        while True:
            data = sock.recvfrom(65535)
            ip_header = data[0][:20]
            ip_src = ipaddress.ip_address(ip_header[12:16])
            packet_type = ip_header[9]

            packets_received += 1
            # Проверка интервала времени для расчета скорости трафика
            if time.time() - start_time >= traffic_interval:
                traffic_rate = packets_received / traffic_interval
                packets_received = 0
                start_time = time.time()
                # Проверка на увеличение скорости трафика
                if traffic_rate > base_traffic_rate:
                    text_widget.insert(tk.END, "**Внимание:** Обнаружено внезапное увеличение трафика!\n")
                    text_widget.see(tk.END)
                # Подсчет количества пакетов для каждого IP-адреса
                ip_counts[ip_src] += 1
                if ip_counts[ip_src] > ip_threshold:
                    text_widget.insert(tk.END, f"**Внимание:** Подозрительная активность с IP-адреса {ip_src}\n")
                    text_widget.see(tk.END)
                    apply_ddos_protection(ip_src)
                # Проверка на тип атакующего пакета
                if packet_type in attack_packet_types:
                    text_widget.insert(tk.END, f"**Внимание:** Обнаружен подозрительный тип пакета: {packet_type}\n")
                    text_widget.see(tk.END)

# Класс для сниффинга сетевого трафика
class Sniffer:
    def __init__(self, interface, store, excluded_ips):
        self.interface = interface
        self.store = store
        self.excluded_ips = excluded_ips
        self.sniff = threading.Thread(target=self.pkt_callback)

    # Метод обработки сниффера
    def pkt_callback(self):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
            sock.bind((self.interface, 0))
            while True:
                data, _ = sock.recvfrom(65535)
                pkt = Ether(data)
                if IP in pkt and pkt[IP].dst == self.interface:
                    if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                        ip_src = pkt[IP].src
                        if ip_src not in self.excluded_ips:
                            total_fwd_packets = 1 if ip_src not in self.store.store else self.store.store[ip_src]['total_fwd_packets'] + 1
                            total_bwd_packets = 0
                            flow_duration = time.time() - self.store.store[ip_src]['time_create'].timestamp()
                            flow_bytes_per_sec = len(pkt) / flow_duration
                            fwd_packet_length_max = len(pkt)
                            fwd_packet_length_min = len(pkt)
                            fwd_packet_length_mean = len(pkt)
                            fwd_packet_length_std = 0
                            # Формирование события
                            event = {
                                "time": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f"),
                                "ip_addr_src": ip_src,
                                "ip_addr_dst": pkt[IP].dst,
                                "port_src": pkt.sport,
                                "port_dst": pkt.dport,
                                "total_fwd_packets": total_fwd_packets,
                                "total_bwd_packets": total_bwd_packets,
                                "flow_duration": flow_duration,
                                "flow_bytes_per_sec": flow_bytes_per_sec,
                                "fwd_packet_length_max": fwd_packet_length_max,
                                "fwd_packet_length_min": fwd_packet_length_min,
                                "fwd_packet_length_mean": fwd_packet_length_mean,
                                "fwd_packet_length_std": fwd_packet_length_std,
                                "protocol": pkt[IP].proto,
                                "packet_length": len(pkt),
                                "flags": pkt.flags
                            }
                            self.store.write(event)

    # Метод для запуска сниффера
    def start(self):
        self.sniff.start()

    # Метод для остановки сниффера
    def stop(self):
        self.sniff.join()


# Класс для анализа событий
class Analytics:
    def __init__(self, store, count_max_events, check_time, model, anomaly_threshold):
        self.store = store
        self.model = model
        self.count_max_events = count_max_events
        self.check_time = check_time
        self.anomaly_threshold = anomaly_threshold
        self.last_log_time = time.time()
        self.prev_traffic_rate = 0

    # Метод для проверки событий
    def check(self, text_widget):
        while True:
            time.sleep(self.check_time)
            self.analyze_traffic(text_widget)

    # Метод для анализа сетевого трафика
    def analyze_traffic(self, text_widget):
        current_time = time.time()
        elapsed_time = current_time - self.last_log_time
        if elapsed_time >= self.check_time:
            self.last_log_time = current_time
            text_widget.insert(tk.END, f'Начало анализа трафика...\n')
            text_widget.see(tk.END)
            if self.detect_traffic_increase():
                text_widget.insert(tk.END, f"Компьютер поддвергается DDoS-атака, IP-адрес с которого совершается атака !")
                text_widget.see(tk.END)
                return
            else:
                text_widget.insert(tk.END, 'Трафик в норме.\n')
                text_widget.see(tk.END)
        anomalies_found = self.detect_anomalies()
        if not anomalies_found:
            text_widget.insert(tk.END, 'Трафик в норме.\n')
            text_widget.see(tk.END)
        else:
            text_widget.insert(tk.END, 'Компьютер поддвергается DDoS-атака\n')
            text_widget.see(tk.END)

    # Метод для обнаружения увеличения трафика
    def detect_traffic_increase(self):
        current_traffic_rate = self.calculate_traffic_rate()
        if current_traffic_rate > self.prev_traffic_rate:
            self.prev_traffic_rate = current_traffic_rate
            return True
        else:
            self.prev_traffic_rate = current_traffic_rate
            return False

    # Метод для расчета скорости трафика
    def calculate_traffic_rate(self):
        total_packets = sum(data['total_fwd_packets'] for data in self.store.read_all().values())
        traffic_rate = total_packets / self.check_time
        return traffic_rate
    # Метод для обнаружения аномалий
    def detect_anomalies(self):
        anomalies_found = False
        for ip, data in list(self.store.read_all().items()):
            count_ip_events = data['total_fwd_packets']
            if count_ip_events >= self.count_max_events:
                self.store.pop(ip)
                if self.model.check_event(data) >= self.anomaly_threshold:
                    anomalies_found = True
                    apply_ddos_protection(ip)
        return anomalies_found
# Метод для применения защиты от DDoS-атак
def apply_ddos_protection(ip_address):
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Заблокирован IP-адрес: {ip_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при применении защиты: {e}")

# Класс для модели
class Model:
    def __init__(self, model_path, data_path, create_model=True):
        self.model_path = model_path
        self.features = None
        if not os.path.isfile(model_path) or create_model:
            self.create_model(data_path)
        self.load_model()

    # Метод для создания меток
    def create_labels(self, labels):
        encoder = LabelEncoder()
        encoder.fit(labels)
        return encoder.transform(labels)

    # Метод для загрузки данных
    def load_data(self, data_path):
        data = pd.read_csv(data_path)
        data = pd.get_dummies(data, sparse=True)
        self.features = data.columns.tolist()[:-1]
        labels = data.iloc[:, -1]
        return data.iloc[:, :-1], labels

    # Метод для создания модели
    def create_model(self, data_path):
        data, labels = self.load_data(data_path)
        train_events, test_events, train_labels, test_labels = train_test_split(data, labels, test_size=0.2, random_state=42)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(train_events, train_labels)
        pickle.dump(self.model, open(self.model_path, 'wb'))

    def load_model(self):
        try:
            self.model = pickle.load(open(self.model_path, 'rb'))
        except FileNotFoundError:
            logging.error('File save model not found')
            exit()

    # Метод для проверки события
    def check_event(self, event_info):
        if not self.features:
            logging.error('Features are not defined. Model not properly initialized.')
            return None
        input_features = [event_info.get(feature, 0) for feature in self.features]
        if not any(input_features):
            logging.error('No valid input features provided.')
            return None
        return self.model.predict_proba([input_features])[0][1]

# Главный класс для приложения
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Программный модуль для обнаружения DDoS-атак")
        self.geometry("680x390")

        self.tabControl = ttk.Notebook(self)

        self.ml_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.ml_tab, text="Машинное обучение")

        self.manual_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.manual_tab, text="Ручной режим")

        self.tabControl.pack(expand=1, fill="both")

        self.setup_ml_tab()
        self.setup_manual_tab()

    # Метод для настройки вкладки машинного обучения
    def setup_ml_tab(self):
        ml_frame = ttk.LabelFrame(self.ml_tab, text="Машинное обучение")
        ml_frame.grid(column=0, row=0, padx=8, pady=4, sticky='nsew')

        model_label = ttk.Label(ml_frame, text="Путь к модели:")
        model_label.grid(column=0, row=0, sticky="W", padx=8, pady=4)
        self.model_entry = ttk.Entry(ml_frame, width=30)
        self.model_entry.grid(column=1, row=0, padx=8, pady=4)
        self.browse_model_button = ttk.Button(ml_frame, text="Обзор", command=self.browse_model_file)
        self.browse_model_button.grid(column=2, row=0, padx=4, pady=4)

        data_label = ttk.Label(ml_frame, text="Путь к данным:")
        data_label.grid(column=0, row=1, sticky="W", padx=8, pady=4)
        self.data_entry = ttk.Entry(ml_frame, width=30)
        self.data_entry.grid(column=1, row=1, padx=8, pady=4)
        self.browse_data_button = ttk.Button(ml_frame, text="Обзор", command=self.browse_data_file)
        self.browse_data_button.grid(column=2, row=1, padx=4, pady=4)

        self.retrain_button = ttk.Button(ml_frame, text="Дообучить на сетевом трафике ", command=self.retrain_model)
        self.retrain_button.grid(column=0, row=3, columnspan=3, padx=8, pady=4)

    # Метод для настройки вкладки ручного режима
    def setup_manual_tab(self):
        manual_frame = ttk.LabelFrame(self.manual_tab, text="Ручной анализ")
        manual_frame.grid(column=0, row=0, padx=8, pady=4)

        iface_label = ttk.Label(manual_frame, text="Имя интерфейса:")
        iface_label.grid(column=0, row=0, sticky="W", padx=8, pady=4)
        self.iface_entry = ttk.Entry(manual_frame, width=30)
        self.iface_entry.grid(column=1, row=0, padx=8, pady=4)

        self.start_button = ttk.Button(manual_frame, text="Начать анализ", command=self.start_analysis)
        self.start_button.grid(column=0, row=1, columnspan=2, padx=8, pady=4)


        self.text_widget = tk.Text(manual_frame, wrap="word", height=10)
        self.text_widget.grid(column=0, row=3, columnspan=2, padx=8, pady=4)

    # Метод для выбора файла модели
    def browse_model_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.model_entry.delete(0, tk.END)
            self.model_entry.insert(tk.END, file_path)

    def browse_data_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.data_entry.delete(0, tk.END)
            self.data_entry.insert(tk.END, file_path)

    # Метод для обучения модели
    def train_model(self):
        model_path = self.model_entry.get()
        data_path = self.data_entry.get()
        if not os.path.isfile(model_path) or not os.path.isfile(data_path):
            messagebox.showerror("Ошибка", "Указаны неверные пути к файлам модели или данных")
            return
        data_store = DataStore()
        model = Model(model_path, data_path)
        sniffer = Sniffer("eth0", data_store, [])
        analytics = Analytics(data_store, 5, 5, model, 0.01)
        sniffer_thread = threading.Thread(name='sniffer', target=sniffer.start)
        analytics_thread = threading.Thread(name='analytics', target=analytics.check, args=(self.ml_text_widget,))
        sniffer_thread.start()
        analytics_thread.start()
        sniffer_thread.join()
        analytics_thread.join()

    # Метод для дообучения модели
    def retrain_model(self):
        from sklearn.ensemble import IsolationForest
        from scapy.layers.inet import IP
        import numpy as np
        import time
        from scapy.all import sniff

        def sniff_traffic_for_seconds(interface="eth0", duration=100):
            start_time = time.time()
            packets = []
            while (time.time() - start_time) < duration:
                new_packets = sniff(iface=interface, count=10)  # Примерно 10 пакетов за раз
                packets.extend(new_packets)
            return packets

        def extract_features(packet):
            # Инициализируем признаки
            features = []

            # Длина пакета
            features.append(len(packet))

            # Протокол, если он доступен
            if IP in packet:
                features.append(packet[IP].proto)
            else:
                features.append(-1)  # Если протокол не определен, добавляем -1

            # Размерность пакетов
            sizes = [len(layer) for layer in packet]
            avg_size = np.mean(sizes)
            std_size = np.std(sizes)
            features.extend([avg_size, std_size])

            return features

        def train_model(data):
            clf = IsolationForest(contamination=0.05)
            clf.fit(data)
            print("Модель успешно обучена.")
            return clf

        from scapy.layers.inet import IP

        def detect_anomalies(model, packet, threshold):
            features = extract_features(packet)
            prediction = model.predict([features])[0]
            if prediction == -1:
                if IP in packet:
                    print(f"Компьютер поддвергается DDoS-атака, IP-адрес с которого совершается атака - {packet[IP].src}!")
                else:
                    print("Обнаружена аномалия: возможна атака! (IP не определен)")
            else:
                print("Трафик в норме.")

        def main():
            print("Обучение модели...")
            # Сниффинг сетевого трафика для определенного количества времени
            packets = sniff_traffic_for_seconds(duration=100)  # Сниффинг в течение 30 секунд

            # Извлечение признаков из пакетов
            data = [extract_features(packet) for packet in packets]

            # Обучение модели на извлеченных признаках
            model = train_model(data)

            print("Начало анализа трафика...")
            # Непрерывный анализ трафика
            start_time = time.time()
            while (time.time() - start_time) < 3600:  # Примерно 1 час
                packet = sniff(iface="eth0", count=1)[0]
                detect_anomalies(model, packet, threshold=0.5)  # Выберите порог в соответствии с вашими потребностями
                # Удаляем обработанный пакет из буфера scapy, чтобы избежать утечек памяти
                del packet
                time.sleep(1)  # Пауза между анализом пакетов

        if __name__ == "__main__":
            main()

    # Метод для начала анализа
    def start_analysis(self):
        print("Функция start_analysis вызвана")
        iface = self.iface_entry.get()
        if not iface:
            messagebox.showerror("Ошибка", "Введите имя интерфейса")
            return
        monitor_thread = threading.Thread(name='traffic_monitor', target=monitor_traffic, args=(iface, self.text_widget))
        monitor_thread.start()
        messagebox.showinfo("Информация", "Анализ сетевого трафика запущен")

# Запуск приложения
if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
    app = MainApp()
    app.setup_manual_tab()  # Добавляем вызов метода setup_manual_tab
    app.mainloop()
