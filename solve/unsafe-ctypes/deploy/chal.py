from base64 import encode
import ctypes
from operator import length_hint
import os
from sys import stdout

path = f'{os.getcwd()}/libchal.so'
dll = ctypes.cdll.LoadLibrary(path)

func = {}

class info(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint64), \
                ("data", ctypes.c_char_p)]

class array(ctypes.Structure):
    _fields_ = [("list", ctypes.POINTER(ctypes.POINTER(info)))]

def set_functions(name, arguments, ret):
    func[name] = getattr(dll, name)
    func[name].argtypes = arguments
    func[name].restype = ret

def initilize():

    set_functions("init_arr", \
        None, \
        ctypes.POINTER(array))

    set_functions("free_array", \
        (ctypes.POINTER(array), ctypes.c_uint64), \
        ctypes.POINTER(array))

    set_functions("malloc_array", \
        (ctypes.POINTER(array), ctypes.c_uint64, ctypes.c_uint64), \
        ctypes.POINTER(array))

    set_functions("read_array", \
        (ctypes.POINTER(array), ctypes.c_uint64), \
        ctypes.c_char_p)

    set_functions("write_array", \
        (ctypes.POINTER(array), ctypes.c_uint64, ctypes.c_char_p), \
        ctypes.POINTER(array))
    
def get_info(information):
    if information:
        return information.hex()
    else:
        return "None"
    

if __name__ == "__main__":
    initilize()
    arr = func['init_arr']()

    while True:
        cmd = input("cmd > ")

        if cmd == "malloc":
            idx = int(input("idx: "))
            if 0 <= idx < 0x10:
                size = int(input("size: "))
                if size > 0:
                    arr = func['malloc_array'](arr, idx, size)
                    print("alloc successed", end="\n\n")
                else:
                    print("invalid size", end="\n\n")
            else:
                print("invalid idx", end="\n\n")
        
        elif cmd == "free":
            idx = int(input("idx: "))
            if 0 <= idx < 0x10:
                arr = func['free_array'](arr, idx)
                print("free successed", end="\n\n")
            else:
                print("invalid idx", end="\n\n")
        
        elif cmd == "read":
            idx = int(input("idx: "))
            if 0 <= idx < 0x10:
                print(f"info: {get_info(func['read_array'](arr, idx))}", end="\n\n")
            else:
                print("invalid idx", end="\n\n")
        
        elif cmd == "modify":
            idx = int(input("idx: "))
            if 0 <= idx < 0x10:
                data = input("data: ")
                arr = func['write_array'](arr, idx, bytes.fromhex(data))
                print("modify successed", end="\n\n")
            else:
                print("invalid idx", end="\n\n")
        elif cmd == "exit":
            break
        else:
            print("invalid command", end="\n\n")


