"""
Сервер захищеного месенджера - З ВЛАСНИМИ OAEP ТА CRT
"""
import socket
import threading
import json
import traceback
from utils import (
    generate_keys, load_keys, write_log,
    encrypt_message, decrypt_message,
    serialize_key, deserialize_key,
    get_timestamp
)

HOST = '127.0.0.1'
PORT = 65432

class MessengerServer:
    def __init__(self):
        # Генерація ключів сервера
        generate_keys("server")
        self.server_priv, self.server_pub = load_keys("server")
        
        # Список клієнтів
        self.clients = {}
        self.client_counter = 0
        self.lock = threading.Lock()
        
        self.debug_mode = True
        
        print("=" * 70)
        print("     ЗАХИЩЕНИЙ МЕСЕНДЖЕР - СЕРВЕР")
        print("     ВЛАСНІ РЕАЛІЗАЦІЇ: OAEP та CRT")
        print("=" * 70)
        print(f"Адреса: {HOST}:{PORT}")
        print(f"Розмір ключа: {self.server_pub.size_in_bits()} біт")
        if hasattr(self.server_priv, 'p'):
            print(f"CRT параметри: p={self.server_priv.p.bit_length()} біт, q={self.server_priv.q.bit_length()} біт")
        print(f"OAEP: ВЛАСНА реалізація з SHA-256")
        print(f"CRT: ВЛАСНА реалізація (оптимізація)")
        print("=" * 70)
        print("Очікування підключень...")
    
    def debug_log(self, message):
        """Відлагоджувальний лог"""
        if self.debug_mode:
            print(f"[DEBUG] {message}")
    
    def broadcast(self, message, sender_id=None, sender_name="Система"):
        """Відправка повідомлення всім клієнтам"""
        self.debug_log(f"Broadcast від {sender_name}: '{message}'")
        
        with self.lock:
            for client_id, client_data in list(self.clients.items()):
                if sender_id is not None and client_id == sender_id:
                    continue
                
                try:
                    self.debug_log(f"Відправка клієнту {client_data['username']}...")
                    
                    data = {
                        'type': 'message',
                        'from': sender_name,
                        'message': message,
                        'timestamp': get_timestamp()
                    }
                    
                    data_json = json.dumps(data, ensure_ascii=False)
                    self.debug_log(f"JSON: {data_json[:50]}...")
                    
                    # Шифруємо з ВАШИМ OAEP
                    encrypted = encrypt_message(data_json, client_data['pub_key'])
                    self.debug_log(f"Зашифровано (власний OAEP): {len(encrypted)} байт")
                    
                    # Відправляємо тільки зашифроване повідомлення (БЕЗ ПІДПИСУ)
                    client_data['conn'].sendall(encrypted)
                    self.debug_log(f"Відправлено {len(encrypted)} байт")
                    
                except Exception as e:
                    print(f"[!] Помилка відправки клієнту {client_id}: {e}")
                    self.debug_log(f"Помилка: {traceback.format_exc()}")
    
    def handle_client(self, conn, addr):
        """Обробка клієнта"""
        client_id = self.client_counter
        self.client_counter += 1
        
        client_ip = addr[0]
        print(f"[+] Клієнт #{client_id} підключився з {client_ip}")
        self.debug_log(f"Нове з'єднання: {addr}")
        
        try:
            # Реєстрація
            self.debug_log("Очікування реєстрації...")
            username, client_pub = self.register_client(conn)
            if not username:
                print(f"[!] Реєстрація клієнта #{client_id} не вдалася")
                conn.close()
                return
            
            self.debug_log(f"Клієнт зареєстрований як '{username}'")
            
            # Додавання клієнта
            with self.lock:
                self.clients[client_id] = {
                    'conn': conn,
                    'username': username,
                    'pub_key': client_pub
                }
            
            # Повідомлення всіх
            self.broadcast(f"{username} приєднався до чату", sender_id=client_id, sender_name="Система")
            
            print(f"[✓] {username} підключився. Онлайн: {len(self.clients)}")
            
            # Привітання
            self.send_welcome(conn, client_pub, username)
            
            # Основний цикл
            while True:
                try:
                    self.debug_log("Очікування даних від клієнта...")
                    data = conn.recv(4096)
                    
                    if not data:
                        self.debug_log("Клієнт відправив порожні дані")
                        break
                    
                    self.debug_log(f"Отримано {len(data)} байт від {username}")
                    
                    try:
                        # Розшифровуємо повідомлення (з ВАШИМИ CRT та OAEP)
                        self.debug_log("Розшифровка (власні CRT та OAEP)...")
                        message_json = decrypt_message(data, self.server_priv)
                        self.debug_log(f"Розшифровано: {message_json[:100]}...")
                        
                        message_data = json.loads(message_json)
                        
                        # Обробляємо повідомлення
                        msg_type = message_data.get('type', 'message')
                        
                        if msg_type == 'message':
                            msg = message_data.get('message', '').strip()
                            if msg:
                                print(f"[{get_timestamp()}] {username}: {msg}")
                                write_log("SERVER", f"Отримано від {username}: {msg}", "INFO")
                                self.debug_log(f"Пересилання повідомлення '{msg}' всім...")
                                self.broadcast(msg, sender_id=client_id, sender_name=username)
                        
                        elif msg_type == 'command':
                            command = message_data.get('command', '')
                            if command == 'users':
                                self.debug_log("Відправка списку користувачів...")
                                self.send_user_list(conn, client_pub, username)
                    
                    except json.JSONDecodeError as e:
                        print(f"[!] Помилка JSON від {username}: {e}")
                        self.debug_log(f"JSON помилка: {e}")
                    except Exception as e:
                        print(f"[!] Помилка обробки повідомлення від {username}: {e}")
                        self.debug_log(f"Помилка: {traceback.format_exc()}")
                        # Відправляємо повідомлення про помилку клієнту
                        self.send_error(conn, client_pub, "Помилка розшифровки повідомлення")
                        
                except ConnectionResetError:
                    print(f"[!] З'єднання з {username} розірвано")
                    self.debug_log("ConnectionResetError")
                    break
                except socket.timeout:
                    self.debug_log("Таймаут сокета")
                    continue
                except Exception as e:
                    print(f"[!] Помилка читання від {username}: {e}")
                    self.debug_log(f"Помилка читання: {traceback.format_exc()}")
                    break
                    
        except Exception as e:
            print(f"[!] Помилка з клієнтом #{client_id}: {e}")
            self.debug_log(f"Загальна помилка: {traceback.format_exc()}")
        finally:
            self.remove_client(client_id)
    
    def register_client(self, conn):
        """Реєстрація клієнта"""
        try:
            # Відправляємо handshake
            handshake = {
                'type': 'handshake',
                'server_key': serialize_key(self.server_pub),
                'status': 'ok'
            }
            handshake_json = json.dumps(handshake)
            self.debug_log(f"Відправка handshake: {handshake_json[:50]}...")
            conn.sendall((handshake_json + '\n').encode())
            
            # Отримуємо дані клієнта
            self.debug_log("Очікування даних клієнта...")
            
            # Спочатку отримуємо довжину даних (4 байти)
            data_length_bytes = conn.recv(4)
            if len(data_length_bytes) < 4:
                self.debug_log("Не отримано довжину даних")
                return None, None
            
            data_length = int.from_bytes(data_length_bytes, 'big')
            self.debug_log(f"Очікувана довжина даних: {data_length} байт")
            
            # Отримуємо самі дані
            data = b""
            while len(data) < data_length:
                chunk = conn.recv(min(4096, data_length - len(data)))
                if not chunk:
                    break
                data += chunk
            
            self.debug_log(f"Отримано {len(data)} байт")
            
            # Декодуємо JSON
            try:
                data_str = data.decode('utf-8')
                self.debug_log(f"Отримані дані: {data_str[:100]}...")
            except UnicodeDecodeError as e:
                self.debug_log(f"Помилка декодування UTF-8: {e}")
                return None, None
            
            if not data_str:
                return None, None
            
            client_data = json.loads(data_str)
            
            username = client_data.get('username', 'Гість')
            client_pub_str = client_data.get('public_key')
            
            if not client_pub_str:
                self.debug_log("Немає публічного ключа")
                return None, None
            
            client_pub = deserialize_key(client_pub_str)
            self.debug_log(f"Ключ клієнта завантажено, розмір: {client_pub.size_in_bits()} біт")
            
            return username, client_pub
            
        except Exception as e:
            print(f"[!] Помилка реєстрації: {e}")
            self.debug_log(f"Помилка реєстрації: {traceback.format_exc()}")
            return None, None
    
    def send_welcome(self, conn, client_pub, username):
        """Відправка привітання"""
        try:
            welcome = {
                'type': 'system',
                'from': 'Сервер',
                'message': f'Ласкаво просимо, {username}! (Використовуються власні OAEP та CRT)',
                'timestamp': get_timestamp()
            }
            welcome_json = json.dumps(welcome)
            self.debug_log(f"Відправка привітання: {welcome_json}")
            
            encrypted = encrypt_message(welcome_json, client_pub)
            conn.sendall(encrypted)
            self.debug_log("Привітання відправлено")
            
        except Exception as e:
            print(f"[!] Помилка привітання: {e}")
            self.debug_log(f"Помилка привітання: {traceback.format_exc()}")
    
    def send_user_list(self, conn, client_pub, username):
        """Відправка списку користувачів"""
        try:
            with self.lock:
                users = [data['username'] for data in self.clients.values()]
            
            user_list = ", ".join(users)
            response = {
                'type': 'system',
                'from': 'Сервер',
                'message': f'Користувачі онлайн ({len(users)}): {user_list}',
                'timestamp': get_timestamp()
            }
            
            response_json = json.dumps(response)
            self.debug_log(f"Відправка списку користувачів: {response_json}")
            
            encrypted = encrypt_message(response_json, client_pub)
            conn.sendall(encrypted)
            self.debug_log("Список користувачів відправлено")
            
        except Exception as e:
            print(f"[!] Помилка відправки списку: {e}")
            self.debug_log(f"Помилка списку: {traceback.format_exc()}")
    
    def send_error(self, conn, client_pub, error_msg):
        """Відправка повідомлення про помилку"""
        try:
            response = {
                'type': 'system',
                'from': 'Сервер',
                'message': f'⚠️ {error_msg}',
                'timestamp': get_timestamp()
            }
            
            response_json = json.dumps(response)
            encrypted = encrypt_message(response_json, client_pub)
            conn.sendall(encrypted)
            
        except:
            pass
    
    def remove_client(self, client_id):
        """Видалення клієнта"""
        if client_id in self.clients:
            username = self.clients[client_id]['username']
            self.debug_log(f"Видалення клієнта {username}")
            
            # Закриваємо з'єднання
            try:
                self.clients[client_id]['conn'].close()
            except:
                pass
            
            # Видаляємо зі списку
            with self.lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            
            # Повідомляємо інших
            self.broadcast(f"{username} покинув чат", sender_name="Система")
            
            print(f"[-] {username} відключився. Онлайн: {len(self.clients)}")
    
    def start(self):
        """Запуск сервера"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen(5)
                
                print(f"[✓] Сервер запущено на {HOST}:{PORT}")
                print("Натисніть Ctrl+C для зупинки\n")
                
                while True:
                    conn, addr = s.accept()
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    thread.start()
                    
        except KeyboardInterrupt:
            print("\n[🛑] Сервер зупинено")
        except Exception as e:
            print(f"[!] Помилка сервера: {e}")
            self.debug_log(f"Критична помилка: {traceback.format_exc()}")

if __name__ == "__main__":
    server = MessengerServer()
    server.start()