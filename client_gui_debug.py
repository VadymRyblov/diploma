"""
Клиент защищенного мессенджера - ОТЛАДОЧНАЯ ВЕРСИЯ
"""
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import json
import time
import traceback
from utils import (
    generate_keys, load_keys, write_log,
    encrypt_message, decrypt_message,
    sign_message, verify_signature,
    serialize_key, deserialize_key,
    get_timestamp
)

HOST = '127.0.0.1'
PORT = 65432

class MessengerClient:
    def __init__(self, master):
        self.master = master
        master.title("Secure Messenger")
        master.geometry("600x500")
        
        # Ключи
        generate_keys("client")
        self.client_priv, self.client_pub = load_keys("client")
        
        # Состояние
        self.client_socket = None
        self.connected = False
        self.username = None
        self.server_pub = None
        self.running = True
        
        # Интерфейс
        self.create_widgets()
        
        # Имя
        self.get_username()
        
        # Подключение
        threading.Thread(target=self.connect_to_server, daemon=True).start()
    
    def create_widgets(self):
        """Создание интерфейса"""
        # Текстовое окно
        self.text_area = scrolledtext.ScrolledText(
            self.master,
            state='disabled',
            wrap=tk.WORD,
            font=('Arial', 10)
        )
        self.text_area.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Цвета
        self.text_area.tag_config('system', foreground='blue')
        self.text_area.tag_config('self', foreground='green')
        self.text_area.tag_config('other', foreground='black')
        self.text_area.tag_config('error', foreground='red')
        self.text_area.tag_config('debug', foreground='orange')
        
        # Ввод
        input_frame = tk.Frame(self.master)
        input_frame.pack(padx=10, pady=5, fill='x')
        
        self.entry = tk.Entry(input_frame, font=('Arial', 11))
        self.entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        self.entry.bind("<Return>", self.send_message)
        self.entry.config(state='disabled')
        
        self.send_button = tk.Button(
            input_frame,
            text="Отправить",
            command=self.send_message,
            state='disabled'
        )
        self.send_button.pack(side='right')
        
        # Статус
        status_frame = tk.Frame(self.master)
        status_frame.pack(padx=10, pady=5, fill='x')
        
        self.status_label = tk.Label(
            status_frame,
            text="❌ Не подключено",
            fg="red"
        )
        self.status_label.pack(side='left')
        
        self.debug_button = tk.Button(
            status_frame,
            text="🔍 Отладка",
            command=self.toggle_debug
        )
        self.debug_button.pack(side='right')
        
        self.debug_mode = False
    
    def toggle_debug(self):
        """Включение/выключение режима отладки"""
        self.debug_mode = not self.debug_mode
        if self.debug_mode:
            self.debug_button.config(text="🔍 Отладка ВКЛ", bg="yellow")
            self.append_text("[ОТЛАДКА] Режим отладки включен", "debug")
        else:
            self.debug_button.config(text="🔍 Отладка", bg="SystemButtonFace")
    
    def debug_log(self, message):
        """Логирование отладочной информации"""
        if self.debug_mode:
            self.append_text(f"[ОТЛАДКА] {message}", "debug")
        print(f"[DEBUG] {message}")
    
    def get_username(self):
        """Получение имени"""
        self.username = simpledialog.askstring("Имя", "Введите ваше имя:", parent=self.master)
        if not self.username:
            self.username = f"Гость_{id(self) % 1000}"
        self.master.title(f"Secure Messenger - {self.username}")
        write_log("CLIENT", f"Клиент инициализирован с именем '{self.username}'", "INFO")
    
    def update_status(self, connected):
        """Обновление статуса"""
        self.connected = connected
        if connected:
            self.status_label.config(text="✅ Подключено", fg="green")
            self.send_button.config(state='normal')
            self.entry.config(state='normal')
            self.entry.focus()
        else:
            self.status_label.config(text="❌ Не подключено", fg="red")
            self.send_button.config(state='disabled')
            self.entry.config(state='disabled')
    
    def connect_to_server(self):
        """Подключение к серверу"""
        try:
            self.append_text("[СИСТЕМА] Подключение к серверу...", "system")
            self.debug_log("Создание сокета...")
            
            # Создание сокета
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            self.debug_log(f"Подключение к {HOST}:{PORT}...")
            sock.connect((HOST, PORT))
            self.debug_log("Подключено к серверу")
            
            # Получение handshake
            self.debug_log("Ожидание handshake...")
            data = sock.recv(4096)
            self.debug_log(f"Получено {len(data)} байт")
            
            if not data:
                raise Exception("Нет ответа от сервера")
            
            try:
                handshake_text = data.decode().strip()
                self.debug_log(f"Handshake: {handshake_text[:50]}...")
                handshake = json.loads(handshake_text)
            except Exception as e:
                self.debug_log(f"Ошибка парсинга handshake: {e}")
                raise
            
            if handshake.get('status') != 'ok':
                raise ValueError("Ошибка подключения")
            
            # Сохраняем ключ сервера
            self.debug_log("Загрузка ключа сервера...")
            self.server_pub = deserialize_key(handshake['server_key'])
            self.debug_log(f"Ключ сервера загружен, размер: {self.server_pub.size_in_bits()} бит")
            
            # Отправляем данные клиента
            client_data = {
                'username': self.username,
                'public_key': serialize_key(self.client_pub)
            }
            client_json = json.dumps(client_data)
            self.debug_log(f"Отправка данных клиента: {len(client_json)} байт")
            sock.sendall(client_json.encode())
            
            self.client_socket = sock
            self.update_status(True)
            self.append_text("[СИСТЕМА] Подключено к серверу", "system")
            write_log("CLIENT", f"Подключено к серверу как '{self.username}'", "INFO")
            
            # Запускаем получение сообщений
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
        except socket.timeout:
            self.debug_log("Таймаут подключения")
            self.append_text("[ОШИБКА] Таймаут подключения", "error")
            messagebox.showerror("Ошибка", "Таймаут подключения к серверу")
        except ConnectionRefusedError:
            self.debug_log("Сервер недоступен")
            self.append_text("[ОШИБКА] Сервер недоступен", "error")
            messagebox.showerror("Ошибка", "Сервер недоступен. Запустите сервер сначала.")
        except Exception as e:
            self.debug_log(f"Ошибка: {e}\n{traceback.format_exc()}")
            self.append_text(f"[ОШИБКА] {e}", "error")
            messagebox.showerror("Ошибка", str(e))
    
    def send_message(self, event=None):
        """Отправка сообщения"""
        if not self.connected or not self.client_socket:
            return
        
        msg = self.entry.get().strip()
        if not msg:
            return
        
        try:
            self.debug_log(f"Отправка сообщения: '{msg}'")
            
            # Формируем сообщение
            data = {
                'type': 'message',
                'message': msg
            }
            data_json = json.dumps(data)
            self.debug_log(f"JSON: {data_json}")
            
            # Шифруем
            self.debug_log("Шифрование...")
            encrypted = encrypt_message(data_json, self.server_pub)
            self.debug_log(f"Зашифровано: {len(encrypted)} байт")
            
            # Подписываем
            self.debug_log("Подписание...")
            signature = sign_message(data_json, self.client_priv)
            self.debug_log(f"Подпись: {len(signature)} байт")
            
            # Отправляем
            packet = signature + b"|||" + encrypted
            self.debug_log(f"Отправка пакета: {len(packet)} байт")
            self.client_socket.sendall(packet)
            self.debug_log("Отправлено")
            
            # Очищаем поле
            self.entry.delete(0, tk.END)
            
            # Показываем у себя
            self.append_text(f"{self.username}: {msg}", "self")
            write_log("CLIENT", f"Отправлено: {msg}", "INFO")
            
        except Exception as e:
            self.debug_log(f"Ошибка отправки: {e}\n{traceback.format_exc()}")
            self.append_text(f"[ОШИБКА] Не удалось отправить: {e}", "error")
    
    def receive_messages(self):
        """Получение сообщений"""
        self.debug_log("Поток получения сообщений запущен")
        
        while self.connected and self.running:
            try:
                self.debug_log("Ожидание данных...")
                data = self.client_socket.recv(4096)
                
                if not data:
                    self.debug_log("Сервер закрыл соединение (пустые данные)")
                    break
                
                self.debug_log(f"Получено {len(data)} байт")
                
                if b"|||" in data:
                    signature, encrypted = data.split(b"|||", 1)
                    self.debug_log(f"Подпись: {len(signature)} байт, зашифровано: {len(encrypted)} байт")
                    
                    try:
                        # Расшифровываем
                        self.debug_log("Расшифровка...")
                        message_json = decrypt_message(encrypted, self.client_priv)
                        self.debug_log(f"Расшифровано: {message_json[:100]}...")
                        
                        message_data = json.loads(message_json)
                        
                        # Проверяем подпись
                        self.debug_log("Проверка подписи...")
                        if verify_signature(message_json, signature, self.server_pub):
                            self.debug_log("Подпись верна")
                            msg_type = message_data.get('type', 'message')
                            
                            if msg_type == 'message':
                                sender = message_data.get('from', 'Неизвестно')
                                msg = message_data.get('message', '')
                                timestamp = message_data.get('timestamp', '')
                                
                                if sender != self.username:
                                    time_str = f"[{timestamp}] " if timestamp else ""
                                    self.append_text(f"{time_str}{sender}: {msg}", "other")
                                    write_log("CLIENT", f"Получено от {sender}: {msg}", "INFO")
                            
                            elif msg_type == 'system':
                                self.append_text(f"[СИСТЕМА] {message_data.get('message', '')}", "system")
                                write_log("CLIENT", f"Системное сообщение: {message_data.get('message', '')}", "INFO")
                        else:
                            self.debug_log("ПОДПИСЬ НЕВЕРНА!")
                            self.append_text("[ПРЕДУПРЕЖДЕНИЕ] Получено сообщение с неверной подписью", "error")
                        
                    except json.JSONDecodeError as e:
                        self.debug_log(f"Ошибка JSON: {e}")
                    except Exception as e:
                        self.debug_log(f"Ошибка обработки: {e}\n{traceback.format_exc()}")
                else:
                    self.debug_log(f"Неверный формат: {data[:50]}...")
                    
            except ConnectionResetError:
                self.debug_log("Соединение разорвано (reset)")
                break
            except socket.timeout:
                self.debug_log("Таймаут получения")
                continue
            except Exception as e:
                self.debug_log(f"Ошибка получения: {e}\n{traceback.format_exc()}")
                if self.connected:
                    break
        
        self.debug_log("Поток получения завершен")
        if self.connected:
            self.master.after(0, self.disconnect)
    
    def append_text(self, text, tag="system"):
        """Добавление текста"""
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text + "\n", tag)
        self.text_area.yview(tk.END)
        self.text_area.config(state='disabled')
    
    def disconnect(self):
        """Отключение"""
        self.debug_log("Отключение...")
        if self.connected:
            self.connected = False
            self.running = False
            
            if self.client_socket:
                try:
                    self.client_socket.close()
                    self.debug_log("Сокет закрыт")
                except:
                    pass
                self.client_socket = None
            
            self.update_status(False)
            self.append_text("[СИСТЕМА] Отключено от сервера", "system")
            write_log("CLIENT", "Отключено от сервера", "INFO")
    
    def on_closing(self):
        """Закрытие окна"""
        self.debug_log("Закрытие окна")
        self.running = False
        self.disconnect()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MessengerClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()