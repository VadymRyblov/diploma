"""
Сервер захищеного месенджера
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"

Що використовується:
  • RSA          — бібліотечний (PyCryptodome)
  • OAEP padding — ВЛАСНА реалізація з BLAKE3 та покращеним MGF1
  • CRT          — бібліотечний (PyCryptodome, застосовується автоматично)
"""
import socket
import threading
import json
import traceback
from utils import (
    generate_keys, load_keys, write_log,
    encrypt_message, decrypt_message,
    serialize_key, deserialize_key,
    get_timestamp,
)

HOST = "127.0.0.1"
PORT = 65432


class MessengerServer:
    def __init__(self):
        # Генерація ключів сервера
        generate_keys("server")
        self.server_priv, self.server_pub = load_keys("server")

        # Список клієнтів: {client_id: {conn, username, pub_key}}
        self.clients: dict = {}
        self.client_counter = 0
        self.lock = threading.Lock()

        self.debug_mode = True

        print("=" * 70)
        print("     ЗАХИЩЕНИЙ МЕСЕНДЖЕР — СЕРВЕР")
        print("     OAEP: ВЛАСНА реалізація (BLAKE3 + покращений MGF1)")
        print("     CRT:  бібліотечний PyCryptodome (автоматично)")
        print("=" * 70)
        print(f"Адреса     : {HOST}:{PORT}")
        print(f"Розмір ключа: {self.server_pub.size_in_bits()} біт")
        print("=" * 70)
        print("Очікування підключень...")

    # ------------------------------------------------------------------ #
    #  Логування                                                           #
    # ------------------------------------------------------------------ #

    def debug_log(self, message: str):
        if self.debug_mode:
            print(f"[DEBUG] {message}")

    # ------------------------------------------------------------------ #
    #  Broadcast                                                           #
    # ------------------------------------------------------------------ #

    def broadcast(self, message: str, sender_id=None, sender_name: str = "Система"):
        """Відправка повідомлення всім клієнтам, крім відправника."""
        self.debug_log(f"Broadcast від {sender_name}: '{message}'")

        with self.lock:
            clients_snapshot = list(self.clients.items())

        for client_id, client_data in clients_snapshot:
            if sender_id is not None and client_id == sender_id:
                continue
            try:
                data = {
                    "type": "message",
                    "from": sender_name,
                    "message": message,
                    "timestamp": get_timestamp(),
                }
                data_json = json.dumps(data, ensure_ascii=False)
                encrypted = encrypt_message(data_json, client_data["pub_key"])
                client_data["conn"].sendall(encrypted)
                self.debug_log(f"Відправлено {len(encrypted)} байт → {client_data['username']}")
            except Exception as e:
                print(f"[!] Помилка відправки клієнту {client_id}: {e}")
                self.debug_log(traceback.format_exc())

    # ------------------------------------------------------------------ #
    #  Обробка клієнта                                                     #
    # ------------------------------------------------------------------ #

    def handle_client(self, conn: socket.socket, addr):
        client_id = self.client_counter
        self.client_counter += 1

        print(f"[+] Клієнт #{client_id} підключився з {addr[0]}")

        try:
            username, client_pub = self.register_client(conn)
            if not username:
                print(f"[!] Реєстрація клієнта #{client_id} не вдалася")
                conn.close()
                return

            with self.lock:
                self.clients[client_id] = {
                    "conn": conn,
                    "username": username,
                    "pub_key": client_pub,
                }

            self.broadcast(f"{username} приєднався до чату", sender_id=client_id, sender_name="Система")
            print(f"[✓] {username} підключився. Онлайн: {len(self.clients)}")
            self.send_welcome(conn, client_pub, username)

            # Основний цикл приймання
            while True:
                try:
                    data = conn.recv(4096)

                    if not data:
                        self.debug_log("Клієнт відправив порожні дані — розрив з'єднання")
                        break

                    self.debug_log(f"Отримано {len(data)} байт від {username}")

                    try:
                        message_json = decrypt_message(data, self.server_priv)
                        self.debug_log(f"Розшифровано: {message_json[:100]}...")
                        message_data = json.loads(message_json)
                        msg_type = message_data.get("type", "message")

                        if msg_type == "message":
                            msg = message_data.get("message", "").strip()
                            if msg:
                                print(f"[{get_timestamp()}] {username}: {msg}")
                                write_log("SERVER", f"Отримано від {username}: {msg}")
                                self.broadcast(msg, sender_id=client_id, sender_name=username)

                        elif msg_type == "command":
                            if message_data.get("command") == "users":
                                self.send_user_list(conn, client_pub)

                    except json.JSONDecodeError as e:
                        print(f"[!] Помилка JSON від {username}: {e}")
                    except Exception as e:
                        print(f"[!] Помилка обробки від {username}: {e}")
                        self.debug_log(traceback.format_exc())
                        self.send_error(conn, client_pub, "Помилка розшифровки повідомлення")

                except ConnectionResetError:
                    print(f"[!] З'єднання з {username} розірвано")
                    break
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Помилка читання від {username}: {e}")
                    self.debug_log(traceback.format_exc())
                    break

        except Exception as e:
            print(f"[!] Помилка з клієнтом #{client_id}: {e}")
            self.debug_log(traceback.format_exc())
        finally:
            self.remove_client(client_id)

    # ------------------------------------------------------------------ #
    #  Реєстрація                                                          #
    # ------------------------------------------------------------------ #

    def register_client(self, conn: socket.socket):
        """Handshake: відправляємо публічний ключ сервера, отримуємо ключ клієнта."""
        try:
            handshake = {
                "type": "handshake",
                "server_key": serialize_key(self.server_pub),
                "status": "ok",
            }
            conn.sendall((json.dumps(handshake) + "\n").encode())
            self.debug_log("Handshake відправлено")

            # Отримуємо довжину (4 байти) + дані
            data_length_bytes = conn.recv(4)
            if len(data_length_bytes) < 4:
                return None, None

            data_length = int.from_bytes(data_length_bytes, "big")
            self.debug_log(f"Очікую {data_length} байт від клієнта")

            data = b""
            while len(data) < data_length:
                chunk = conn.recv(min(4096, data_length - len(data)))
                if not chunk:
                    break
                data += chunk

            client_data = json.loads(data.decode("utf-8"))
            username       = client_data.get("username", "Гість")
            client_pub_str = client_data.get("public_key")

            if not client_pub_str:
                return None, None

            client_pub = deserialize_key(client_pub_str)
            self.debug_log(f"Ключ клієнта '{username}': {client_pub.size_in_bits()} біт")

            return username, client_pub

        except Exception as e:
            print(f"[!] Помилка реєстрації: {e}")
            self.debug_log(traceback.format_exc())
            return None, None

    # ------------------------------------------------------------------ #
    #  Службові повідомлення                                               #
    # ------------------------------------------------------------------ #

    def _send_system(self, conn: socket.socket, client_pub, text: str):
        msg = {
            "type": "system",
            "from": "Сервер",
            "message": text,
            "timestamp": get_timestamp(),
        }
        encrypted = encrypt_message(json.dumps(msg), client_pub)
        conn.sendall(encrypted)

    def send_welcome(self, conn: socket.socket, client_pub, username: str):
        try:
            self._send_system(
                conn, client_pub,
                f"Ласкаво просимо, {username}! "
                f"(OAEP: власна реалізація BLAKE3 | CRT: бібліотечний)",
            )
        except Exception as e:
            print(f"[!] Помилка привітання: {e}")

    def send_user_list(self, conn: socket.socket, client_pub):
        try:
            with self.lock:
                users = [d["username"] for d in self.clients.values()]
            self._send_system(conn, client_pub, f"Онлайн ({len(users)}): {', '.join(users)}")
        except Exception as e:
            print(f"[!] Помилка списку користувачів: {e}")

    def send_error(self, conn: socket.socket, client_pub, error_msg: str):
        try:
            self._send_system(conn, client_pub, f"⚠️ {error_msg}")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Видалення клієнта                                                   #
    # ------------------------------------------------------------------ #

    def remove_client(self, client_id: int):
        with self.lock:
            client_data = self.clients.pop(client_id, None)

        if client_data:
            try:
                client_data["conn"].close()
            except Exception:
                pass
            username = client_data["username"]
            self.broadcast(f"{username} покинув чат", sender_name="Система")
            print(f"[-] {username} відключився. Онлайн: {len(self.clients)}")

    # ------------------------------------------------------------------ #
    #  Запуск                                                              #
    # ------------------------------------------------------------------ #

    def start(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen(5)
                print(f"[✓] Сервер запущено на {HOST}:{PORT}")
                print("Натисніть Ctrl+C для зупинки\n")

                while True:
                    conn, addr = s.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True,
                    ).start()

        except KeyboardInterrupt:
            print("\n[🛑] Сервер зупинено")
        except Exception as e:
            print(f"[!] Критична помилка сервера: {e}")
            self.debug_log(traceback.format_exc())


if __name__ == "__main__":
    server = MessengerServer()
    server.start()
