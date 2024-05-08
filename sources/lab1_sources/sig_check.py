import winreg
import ctypes
import wmi
import os
import hashlib

def check(signature:str) -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Prikhodko")
        stored_signature, _ = winreg.QueryValueEx(key, 'signature')
        winreg.CloseKey(key)
    except:
        return False
    return stored_signature == signature


def get_system_info_hash() -> str:
    mouse_buttons = ctypes.windll.user32.GetSystemMetrics(43)
    screen_height = ctypes.windll.user32.GetSystemMetrics(1)

    c = wmi.WMI()
    disk_info = [(disk.Caption, disk.VolumeSerialNumber) for disk in c.Win32_LogicalDisk()]

    username = os.getlogin()
    compname = os.environ['COMPUTERNAME']

    windows_folder = os.environ['WINDIR']
    system32_folder = os.path.join(windows_folder, 'System32')


    info_str = f"{username}{compname}{windows_folder}{system32_folder}{mouse_buttons}{screen_height}{disk_info}"


    info_hash = hashlib.sha256(info_str.encode()).hexdigest()

    return info_hash


