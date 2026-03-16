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
    serialize_key, deserialize_key,
    get_timestamp
)

HOST = '127.0.0.1'
PORT = 65432

class MessengerClient:
    def __init__(self, master):
        self.master = master
        master.title("Secure Messenger (Власні OAEP та CRT)")
        master.geometry("600x500")
        
        # Ключі
        generate_keys("client")
        self.client_priv, self.client_pub = load_keys("client")
        
        # Стан
        self.client_socket = None
        self.connected = False
        self.username = None
        self.server_pub = None
        self.running = True
        self.socket_lock = threading.Lock()
        
        # Інтерфейс
        self.create_widgets()
        
        # Ім'я
        self.get_username()
        
        # Підключення
        threading.Thread(target=self.connect_to_server, daemon=True).start()
    
    def create_widgets(self):
        """Створення інтерфейсу"""
        # Текстове вікно
        self.text_area = scrolledtext.ScrolledText(
            self.master,
            state='disabled',
            wrap=tk.WORD,
            font=('Arial', 10)
        )
        self.text_area.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Кольори
        self.text_area.tag_config('system', foreground='blue')
        self.text_area.tag_config('self', foreground='green')
        self.text_area.tag_config('other', foreground='black')
        self.text_area.tag_config('error', foreground='red')
        self.text_area.tag_config('debug', foreground='orange')
        self.text_area.tag_config('success', foreground='purple')
        
        # Введення
        input_frame = tk.Frame(self.master)
        input_frame.pack(padx=10, pady=5, fill='x')
        
        self.entry = tk.Entry(input_frame, font=('Arial', 11))
        self.entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        self.entry.bind("<Return>", self.send_message)
        self.entry.config(state='disabled')
        
        self.send_button = tk.Button(
            input_frame,
            text="Відправити",
            command=self.send_message,
            state='disabled'
        )
        self.send_button.pack(side='right')
        
        # Статус
        status_frame = tk.Frame(self.master)
        status_frame.pack(padx=10, pady=5, fill='x')
        
        self.status_label = tk.Label(
            status_frame,
            text="❌ Не підключено",
            fg="red"
        )
        self.status_label.pack(side='left')
        
        self.debug_button = tk.Button(
            status_frame,
            text="🔍 Налагодження",
            command=self.toggle_debug
        )
        self.debug_button.pack(side='right')
        
        self.debug_mode = False
    
    def toggle_debug(self):
        """Включення/виключення режиму налагодження"""
        self.debug_mode = not self.debug_mode
        if self.debug_mode:
            self.debug_button.config(text="🔍 Налагодження УВІМК", bg="yellow")
            self.append_text("[НАЛАГОДЖЕННЯ] Режим налагодження увімкнено", "debug")
        else:
            self.debug_button.config(text="🔍 Налагодження", bg="SystemButtonFace")
    
    def debug_log(self, message):
        """Логування налагоджувальної інформації"""
        if self.debug_mode:
            self.append_text(f"[НАЛАГОДЖЕННЯ] {message}", "debug")
        print(f"[DEBUG] {message}")
    
    def get_username(self):
        """Отримання імені"""
        self.username = simpledialog.askstring("Ім'я", "Введіть ваше ім'я:", parent=self.master)
        if not self.username:
            self.username = f"Гість_{id(self) % 1000}"
        self.master.title(f"Secure Messenger - {self.username} (власні OAEP/CRT)")
        write_log("CLIENT", f"Клієнт ініціалізовано з ім'ям '{self.username}'", "INFO")
    
    def update_status(self, connected):
        """Оновлення статусу"""
        self.connected = connected
        if connected:
            self.status_label.config(text="✅ Підключено", fg="green")
            self.send_button.config(state='normal')
            self.entry.config(state='normal')
            self.entry.focus()
        else:
            self.status_label.config(text="❌ Не підключено", fg="red")
            self.send_button.config(state='disabled')
            self.entry.config(state='disabled')
    
    def connect_to_server(self):
        """Підключення до сервера"""
        try:
            self.append_text("[СИСТЕМА] Підключення до сервера...", "system")
            self.debug_log("Створення сокета...")
            
            # Створення сокета
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            self.debug_log(f"Підключення до {HOST}:{PORT}...")
            sock.connect((HOST, PORT))
            self.debug_log("Підключено до сервера")
            
            # Забираємо таймаут для основного циклу
            sock.settimeout(None)
            
            # Отримання handshake
            self.debug_log("Очікування handshake...")
            data = sock.recv(4096)
            self.debug_log(f"Отримано {len(data)} байт")
            
            if not data:
                raise Exception("Немає відповіді від сервера")
            
            try:
                handshake_text = data.decode().strip()
                self.debug_log(f"Handshake: {handshake_text[:50]}...")
                handshake = json.loads(handshake_text)
            except Exception as e:
                self.debug_log(f"Помилка парсингу handshake: {e}")
                raise
            
            if handshake.get('status') != 'ok':
                raise ValueError("Помилка підключення")
            
            # Зберігаємо ключ сервера
            self.debug_log("Завантаження ключа сервера...")
            self.server_pub = deserialize_key(handshake['server_key'])
            self.debug_log(f"Ключ сервера завантажено, розмір: {self.server_pub.size_in_bits()} біт")
            
            # Відправляємо дані клієнта
            client_data = {
                'username': self.username,
                'public_key': serialize_key(self.client_pub)
            }
            client_json = json.dumps(client_data)
            client_bytes = client_json.encode('utf-8')
            
            # Спочатку відправляємо довжину даних (4 байти)
            data_length = len(client_bytes)
            self.debug_log(f"Довжина даних: {data_length} байт")
            sock.sendall(data_length.to_bytes(4, 'big'))
            
            # Потім відправляємо самі дані
            self.debug_log(f"Відправка даних клієнта: {data_length} байт")
            sock.sendall(client_bytes)
            
            with self.socket_lock:
                self.client_socket = sock
            self.update_status(True)
            self.append_text("[СИСТЕМА] Підключено до сервера", "system")
            write_log("CLIENT", f"Підключено до сервера як '{self.username}'", "INFO")
            
            # Запускаємо отримання повідомлень
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
        except socket.timeout:
            self.debug_log("Таймаут підключення")
            self.append_text("[ПОМИЛКА] Таймаут підключення", "error")
            messagebox.showerror("Помилка", "Таймаут підключення до сервера")
        except ConnectionRefusedError:
            self.debug_log("Сервер недоступний")
            self.append_text("[ПОМИЛКА] Сервер недоступний", "error")
            messagebox.showerror("Помилка", "Сервер недоступний. Запустіть сервер спочатку.")
        except Exception as e:
            self.debug_log(f"Помилка: {e}\n{traceback.format_exc()}")
            self.append_text(f"[ПОМИЛКА] {e}", "error")
            messagebox.showerror("Помилка", str(e))
    
    def send_message(self, event=None):
        """Відправка повідомлення"""
        if not self.connected or not self.client_socket:
            return
        
        msg = self.entry.get().strip()
        if not msg:
            return
        
        try:
            self.debug_log(f"Відправка повідомлення: '{msg}'")
            
            # Формуємо повідомлення
            data = {
                'type': 'message',
                'from': self.username,
                'message': msg,
                'timestamp': get_timestamp()
            }
            data_json = json.dumps(data, ensure_ascii=False)
            self.debug_log(f"JSON: {data_json}")
            
            # Шифруємо публічним ключем сервера (з ВАШИМ OAEP)
            self.debug_log("Шифрування (власний OAEP)...")
            encrypted = encrypt_message(data_json, self.server_pub)
            self.debug_log(f"Зашифровано: {len(encrypted)} байт")
            
            # Відправляємо тільки зашифроване повідомлення (БЕЗ ПІДПИСУ)
            with self.socket_lock:
                if self.client_socket and self.connected:
                    self.client_socket.sendall(encrypted)
                    self.debug_log("Відправлено")
                    
                    # Показуємо у себе
                    self.append_text(f"{self.username}: {msg}", "self")
                    write_log("CLIENT", f"Відправлено: {msg}", "INFO")
                else:
                    self.debug_log("Сокет закрито, повідомлення не відправлено")
                    return
            
            # Очищаємо поле
            self.entry.delete(0, tk.END)
            
        except Exception as e:
            self.debug_log(f"Помилка відправки: {e}\n{traceback.format_exc()}")
            self.append_text(f"[ПОМИЛКА] Не вдалося відправити: {e}", "error")
    
    def receive_messages(self):
        """Отримання повідомлень"""
        self.debug_log("Потік отримання повідомлень запущено")
        
        while self.running:
            try:
                if not self.connected:
                    time.sleep(0.1)
                    continue
                
                with self.socket_lock:
                    if not self.client_socket or not self.connected:
                        time.sleep(0.1)
                        continue
                    sock = self.client_socket
                
                # Встановлюємо невеликий таймаут
                sock.settimeout(0.5)
                
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    self.debug_log("З'єднання розірвано (reset)")
                    break
                except Exception as e:
                    if self.connected:
                        self.debug_log(f"Помилка recv: {e}")
                    continue
                
                if not data:
                    self.debug_log("Сервер закрив з'єднання (порожні дані)")
                    break
                
                self.debug_log(f"Отримано {len(data)} байт")
                
                # Розшифровуємо отримані дані (CRT та OAEP)
                try:
                    self.debug_log("Розшифровка (власні CRT та OAEP)...")
                    message_json = decrypt_message(data, self.client_priv)
                    self.debug_log(f"Розшифровано: {message_json[:100]}...")
                    
                    message_data = json.loads(message_json)
                    
                    # Визначаємо тип повідомлення
                    msg_type = message_data.get('type', 'message')
                    msg_from = message_data.get('from', 'Невідомо')
                    msg_text = message_data.get('message', '')
                    msg_time = message_data.get('timestamp', '')
                    
                    # Для системних повідомлень
                    if msg_type == 'system':
                        self.append_text(f"[СИСТЕМА] {msg_text}", "system")
                        write_log("CLIENT", f"Системне повідомлення: {msg_text}", "INFO")
                        continue
                    
                    # Показуємо повідомлення, якщо воно не від себе
                    if msg_from != self.username:
                        time_str = f"[{msg_time}] " if msg_time else ""
                        self.append_text(f"{time_str}{msg_from}: {msg_text}", "other")
                        write_log("CLIENT", f"Отримано від {msg_from}: {msg_text}", "INFO")
                    else:
                        # Це наше повідомлення, яке повернулося від сервера - ігноруємо
                        self.debug_log("Своє повідомлення від сервера - ігноруємо")
                    
                except json.JSONDecodeError as e:
                    self.debug_log(f"Помилка JSON: {e}")
                except Exception as e:
                    self.debug_log(f"Помилка обробки: {e}\n{traceback.format_exc()}")
                    self.append_text(f"[ПОМИЛКА] Не вдалося розшифрувати повідомлення", "error")
                    
            except Exception as e:
                self.debug_log(f"Помилка отримання: {e}\n{traceback.format_exc()}")
                if self.connected:
                    break
        
        self.debug_log("Потік отримання завершено")
        if self.connected:
            self.master.after(0, self.disconnect)
    
    def append_text(self, text, tag="system"):
        """Додавання тексту"""
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, text + "\n", tag)
        self.text_area.yview(tk.END)
        self.text_area.config(state='disabled')
    
    def disconnect(self):
        """Відключення"""
        self.debug_log("Відключення...")
        
        with self.socket_lock:
            if self.connected:
                self.connected = False
                self.running = False
                
                if self.client_socket:
                    try:
                        self.client_socket.close()
                        self.debug_log("Сокет закрито")
                    except:
                        pass
                    self.client_socket = None
            
            self.update_status(False)
        
        self.append_text("[СИСТЕМА] Відключено від сервера", "system")
        write_log("CLIENT", "Відключено від сервера", "INFO")
    
    def on_closing(self):
        """Закриття вікна"""
        self.debug_log("Закриття вікна")
        self.running = False
        self.disconnect()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MessengerClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()