"""
Запуск всіх тестів проекту
"""
import os
import sys
import time

# Додаємо шлях до батьківської папки
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Кольори для виводу (опціонально)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    """Друк заголовку"""
    print(f"\n{Colors.BLUE}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text:^80}{Colors.END}")
    print(f"{Colors.BLUE}{'=' * 80}{Colors.END}\n")

def print_success(text):
    """Друк успішного повідомлення"""
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_error(text):
    """Друк помилки"""
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_info(text):
    """Друк інформації"""
    print(f"{Colors.YELLOW}ℹ️ {text}{Colors.END}")

def run_test(test_name, description):
    """Запуск конкретного тесту"""
    print_header(f" ТЕСТ: {description} ")
    print_info(f"Запуск файлу: {test_name}")
    print()
    
    test_path = os.path.join(os.path.dirname(__file__), test_name)
    
    if not os.path.exists(test_path):
        print_error(f"Файл не знайдено: {test_path}")
        return False
    
    start_time = time.time()
    
    # Запускаємо тест
    result = os.system(f'python "{test_path}"')
    
    end_time = time.time()
    
    if result == 0:
        print_success(f"Тест завершено успішно за {end_time - start_time:.2f} сек")
        return True
    else:
        print_error(f"Тест завершився з помилкою (код {result})")
        return False

def main():
    """Головна функція"""
    print_header(" ЗАПУСК ВСІХ ТЕСТІВ ПРОЕКТУ ")
    
    print_info("Дипломний проект: Захищений обмін повідомленнями")
    print_info("Власні реалізації: OAEP та CRT")
    print_info("Час запуску: " + time.strftime("%Y-%m-%d %H:%M:%S"))
    
    # Список тестів для запуску
    tests = [
        ("test_oaep.py", "Тестування власної реалізації OAEP"),
        ("test_crt.py", "Тестування CRT оптимізації"),
    ]
    
    results = []
    
    for test_file, description in tests:
        success = run_test(test_file, description)
        results.append((test_file, success))
        print("\n" + "-" * 80 + "\n")
    
    # Підсумки
    print_header(" ПІДСУМКИ ТЕСТУВАННЯ ")
    
    all_passed = True
    for test_file, success in results:
        if success:
            print_success(f"{test_file}: УСПІШНО")
        else:
            print_error(f"{test_file}: ПОМИЛКА")
            all_passed = False
    
    print()
    if all_passed:
        print_success("✅ ВСІ ТЕСТИ ПРОЙДЕНО УСПІШНО!")
        print_info("Власні реалізації OAEP та CRT працюють коректно.")
    else:
        print_error("❌ ДЕЯКІ ТЕСТИ НЕ ПРОЙДЕНО")
        print_info("Перевірте помилки вище.")
    
    print(f"\n{Colors.BLUE}{'=' * 80}{Colors.END}")

if __name__ == "__main__":
    main()