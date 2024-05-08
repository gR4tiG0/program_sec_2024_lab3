from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from json import dumps
import winreg
import os


def checkPass(password:str):
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Prikhodko")
    stored_phrase, _ = winreg.QueryValueEx(key, 'passphrase')
    stored_salt, _ = winreg.QueryValueEx(key, 'salt')

    if md5((password + stored_salt).encode()).hexdigest() != stored_phrase:
        return None

    salt = os.urandom(16)
    hashed_sess = md5((password + salt.hex()).encode()).hexdigest()
    winreg.SetValueEx(key, 'passphrase', 0, winreg.REG_SZ, hashed_sess)
    winreg.SetValueEx(key, 'salt', 0, winreg.REG_SZ, salt.hex())
    winreg.CloseKey(key)
    return stored_salt


def decrBase(password:str, salt:str, data:bytes) -> str:
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_ECB)
    data = unpad(cipher.decrypt(data), AES.block_size).decode()
    return data

def encrBase(password:str, salt:str, data:str) -> str:
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_ECB)
    data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return data

def encrEndBase(password:str, data:dict) -> bytes:
    regkey = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Prikhodko")
    salt, _ = winreg.QueryValueEx(regkey, 'salt')
    winreg.CloseKey(regkey)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_ECB)
    data = cipher.encrypt(pad(dumps(data).encode(), AES.block_size))
    return data