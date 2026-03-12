"""
Сервер защищенного мессенджера - С CRT ПОДДЕРЖКОЙ
"""
import socket
import threading
import json
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

class MessengerServer:
    def __init__(self):
        # Генерация ключей сервера
        generate_keys("server")
        self.server_priv, self.server_pub = load_keys("server")
        
        # Список клиентов
        self.clients = {}
        self.client_counter = 0
        self.lock = threading.Lock()
        
        self.debug_mode = True
        
        print("=" * 60)
        print("     ЗАЩИЩЕННЫЙ МЕССЕНДЖЕР - СЕРВЕР (CRT)")
        print("=" * 60)
        print(f"Адрес: {HOST}:{PORT}")
        print(f"Размер ключа: {self.server_pub.size_in_bits()} бит")
        if hasattr(self.server_priv, 'p'):
            print(f"CRT параметры: p={self.server_priv.p.bit_length()} бит, q={self.server_priv.q.bit_length()} бит")
        print("=" * 60)
        print("Ожидание подключений...")
    
    def debug_log(self, message):
        """Отладочный лог"""
        if self.debug_mode:
            print(f"[DEBUG] {message}")
    
    def broadcast(self, message, sender_id=None, sender_name="Система"):
        """Отправка сообщения всем клиентам"""
        self.debug_log(f"Broadcast от {sender_name}: '{message}'")
        
        with self.lock:
            for client_id, client_data in list(self.clients.items()):
                if sender_id is not None and client_id == sender_id:
                    continue
                
                try:
                    self.debug_log(f"Отправка клиенту {client_data['username']}...")
                    
                    data = {
                        'type': 'message',
                        'from': sender_name,
                        'message': message,
                        'timestamp': get_timestamp()
                    }
                    
                    data_json = json.dumps(data, ensure_ascii=False)
                    self.debug_log(f"JSON: {data_json[:50]}...")
                    
                    encrypted = encrypt_message(data_json, client_data['pub_key'])
                    self.debug_log(f"Зашифровано: {len(encrypted)} байт")
                    
                    signature = sign_message(data_json, self.server_priv)
                    self.debug_log(f"Подпись: {len(signature)} байт")
                    
                    packet = signature + b"|||" + encrypted
                    client_data['conn'].sendall(packet)
                    self.debug_log(f"Отправлено {len(packet)} байт")
                    
                except Exception as e:
                    print(f"[!] Ошибка отправки клиенту {client_id}: {e}")
                    self.debug_log(f"Ошибка: {traceback.format_exc()}")
    
    def handle_client(self, conn, addr):
        """Обработка клиента"""
        client_id = self.client_counter
        self.client_counter += 1
        
        client_ip = addr[0]
        print(f"[+] Клиент #{client_id} подключился с {client_ip}")
        self.debug_log(f"Новое соединение: {addr}")
        
        try:
            # Регистрация
            self.debug_log("Ожидание регистрации...")
            username, client_pub = self.register_client(conn)
            if not username:
                print(f"[!] Регистрация клиента #{client_id} не удалась")
                conn.close()
                return
            
            self.debug_log(f"Клиент зарегистрирован как '{username}'")
            
            # Добавление клиента
            with self.lock:
                self.clients[client_id] = {
                    'conn': conn,
                    'username': username,
                    'pub_key': client_pub
                }
            
            # Уведомление всех
            self.broadcast(f"{username} присоединился к чату", sender_id=client_id, sender_name="Система")
            
            print(f"[✓] {username} подключился. Онлайн: {len(self.clients)}")
            
            # Приветствие
            self.send_welcome(conn, client_pub, username)
            
            # Основной цикл
            while True:
                try:
                    self.debug_log("Ожидание данных от клиента...")
                    data = conn.recv(4096)
                    
                    if not data:
                        self.debug_log("Клиент отправил пустые данные")
                        break
                    
                    self.debug_log(f"Получено {len(data)} байт от {username}")
                    
                    if b"|||" not in data:
                        self.debug_log(f"Неверный формат: {data[:50]}...")
                        continue
                    
                    signature, encrypted = data.split(b"|||", 1)
                    self.debug_log(f"Подпись: {len(signature)} байт, зашифровано: {len(encrypted)} байт")
                    
                    try:
                        # Расшифровываем сообщение (с CRT)
                        self.debug_log("Расшифровка...")
                        message_json = decrypt_message(encrypted, self.server_priv)
                        self.debug_log(f"Расшифровано: {message_json[:100]}...")
                        
                        message_data = json.loads(message_json)
                        
                        # Получаем ключ клиента из словаря
                        client_pub = self.clients[client_id]['pub_key']
                        
                        # Проверяем подпись
                        self.debug_log("Проверка подписи...")
                        if not verify_signature(message_json, signature, client_pub):
                            print(f"[!] Неверная подпись от {username}")
                            self.debug_log("ПОДПИСЬ НЕВЕРНА!")
                            continue
                        
                        self.debug_log("Подпись верна ✅")
                        
                        # Обрабатываем сообщение
                        msg_type = message_data.get('type', 'message')
                        
                        if msg_type == 'message':
                            msg = message_data.get('message', '').strip()
                            if msg:
                                print(f"[{get_timestamp()}] {username}: {msg}")
                                # Добавляем запись в лог о полученном сообщении
                                write_log("SERVER", f"Получено от {username}: {msg}", "INFO")
                                self.debug_log(f"Пересылка сообщения '{msg}' всем...")
                                self.broadcast(msg, sender_id=client_id, sender_name=username)
                        
                        elif msg_type == 'command':
                            command = message_data.get('command', '')
                            if command == 'users':
                                self.debug_log("Отправка списка пользователей...")
                                self.send_user_list(conn, client_pub, username)
                    
                    except json.JSONDecodeError as e:
                        print(f"[!] Ошибка JSON от {username}: {e}")
                        self.debug_log(f"JSON ошибка: {e}")
                    except Exception as e:
                        print(f"[!] Ошибка обработки сообщения от {username}: {e}")
                        self.debug_log(f"Ошибка: {traceback.format_exc()}")
                        
                except ConnectionResetError:
                    print(f"[!] Соединение с {username} разорвано")
                    self.debug_log("ConnectionResetError")
                    break
                except socket.timeout:
                    self.debug_log("Таймаут сокета")
                    continue
                except Exception as e:
                    print(f"[!] Ошибка чтения от {username}: {e}")
                    self.debug_log(f"Ошибка чтения: {traceback.format_exc()}")
                    break
                    
        except Exception as e:
            print(f"[!] Ошибка с клиентом #{client_id}: {e}")
            self.debug_log(f"Общая ошибка: {traceback.format_exc()}")
        finally:
            self.remove_client(client_id)
    
    def register_client(self, conn):
        """Регистрация клиента"""
        try:
            # Отправляем handshake
            handshake = {
                'type': 'handshake',
                'server_key': serialize_key(self.server_pub),
                'status': 'ok'
            }
            handshake_json = json.dumps(handshake)
            self.debug_log(f"Отправка handshake: {handshake_json[:50]}...")
            conn.sendall((handshake_json + '\n').encode())
            
            # Получаем данные клиента
            self.debug_log("Ожидание данных клиента...")
            
            # Сначала получаем длину данных (4 байта)
            data_length_bytes = conn.recv(4)
            if len(data_length_bytes) < 4:
                self.debug_log("Не получена длина данных")
                return None, None
            
            data_length = int.from_bytes(data_length_bytes, 'big')
            self.debug_log(f"Ожидаемая длина данных: {data_length} байт")
            
            # Получаем сами данные
            data = b""
            while len(data) < data_length:
                chunk = conn.recv(min(4096, data_length - len(data)))
                if not chunk:
                    break
                data += chunk
            
            self.debug_log(f"Получено {len(data)} байт")
            
            # Декодируем JSON
            try:
                data_str = data.decode('utf-8')
                self.debug_log(f"Получены данные: {data_str[:100]}...")
            except UnicodeDecodeError as e:
                self.debug_log(f"Ошибка декодирования UTF-8: {e}")
                return None, None
            
            if not data_str:
                return None, None
            
            client_data = json.loads(data_str)
            
            username = client_data.get('username', 'Гость')
            client_pub_str = client_data.get('public_key')
            
            if not client_pub_str:
                self.debug_log("Нет публичного ключа")
                return None, None
            
            client_pub = deserialize_key(client_pub_str)
            self.debug_log(f"Ключ клиента загружен, размер: {client_pub.size_in_bits()} бит")
            
            return username, client_pub
            
        except Exception as e:
            print(f"[!] Ошибка регистрации: {e}")
            self.debug_log(f"Ошибка регистрации: {traceback.format_exc()}")
            return None, None
    
    def send_welcome(self, conn, client_pub, username):
        """Отправка приветствия"""
        try:
            welcome = {
                'type': 'system',
                'from': 'Сервер',
                'message': f'Добро пожаловать, {username}!',
                'timestamp': get_timestamp()
            }
            welcome_json = json.dumps(welcome)
            self.debug_log(f"Отправка приветствия: {welcome_json}")
            
            encrypted = encrypt_message(welcome_json, client_pub)
            signature = sign_message(welcome_json, self.server_priv)
            
            packet = signature + b"|||" + encrypted
            conn.sendall(packet)
            self.debug_log("Приветствие отправлено")
            
        except Exception as e:
            print(f"[!] Ошибка приветствия: {e}")
            self.debug_log(f"Ошибка приветствия: {traceback.format_exc()}")
    
    def send_user_list(self, conn, client_pub, username):
        """Отправка списка пользователей"""
        try:
            with self.lock:
                users = [data['username'] for data in self.clients.values()]
            
            user_list = ", ".join(users)
            response = {
                'type': 'system',
                'from': 'Сервер',
                'message': f'Пользователи онлайн ({len(users)}): {user_list}',
                'timestamp': get_timestamp()
            }
            
            response_json = json.dumps(response)
            self.debug_log(f"Отправка списка пользователей: {response_json}")
            
            encrypted = encrypt_message(response_json, client_pub)
            signature = sign_message(response_json, self.server_priv)
            
            conn.sendall(signature + b"|||" + encrypted)
            self.debug_log("Список пользователей отправлен")
            
        except Exception as e:
            print(f"[!] Ошибка отправки списка: {e}")
            self.debug_log(f"Ошибка списка: {traceback.format_exc()}")
    
    def remove_client(self, client_id):
        """Удаление клиента"""
        if client_id in self.clients:
            username = self.clients[client_id]['username']
            self.debug_log(f"Удаление клиента {username}")
            
            # Закрываем соединение
            try:
                self.clients[client_id]['conn'].close()
            except:
                pass
            
            # Удаляем из списка
            with self.lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            
            # Уведомляем остальных
            self.broadcast(f"{username} покинул чат", sender_name="Система")
            
            print(f"[-] {username} отключился. Онлайн: {len(self.clients)}")
    
    def start(self):
        """Запуск сервера"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen(5)
                
                print(f"[✓] Сервер запущен на {HOST}:{PORT}")
                print("Нажмите Ctrl+C для остановки\n")
                
                while True:
                    conn, addr = s.accept()
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    thread.start()
                    
        except KeyboardInterrupt:
            print("\n[🛑] Сервер остановлен")
        except Exception as e:
            print(f"[!] Ошибка сервера: {e}")
            self.debug_log(f"Критическая ошибка: {traceback.format_exc()}")

if __name__ == "__main__":
    server = MessengerServer()
    server.start()