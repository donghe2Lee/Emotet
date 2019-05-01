import re
from idc import *
from idautils import *
from idaapi import *


def bytes_to_int(bytes, i):
    intLL = ord(bytes[i])
    intLH = ord(bytes[i + 1]) << 8
    intHL = ord(bytes[i + 2]) << 16
    intHH = ord(bytes[i + 3]) << 24

    return intLL | intLH | intHL | intHH

def get_specific_address(_st_addr, _ed_addr, _cmd, _opnd_num, _opnd):
    cur_addr = _st_addr

    while cur_addr <= _ed_addr:
        cur_addr = NextHead(cur_addr, _ed_addr)

        if GetMnem(cur_addr) == _cmd:
            if _opnd_num != -1 and _opnd in GetOpnd(cur_addr, _opnd_num):
                return cur_addr
            if _opnd_num == -1:
                return cur_addr

    return 0

def dump_encrypt_data(file_name, encrypt_address, encrypt_size, block, padding):
    f_enc_dump = open(file_name, "wb")
    read_encrypt_address = encrypt_address
    for offset in range(0, encrypt_size, block):
        read_bytes = 0

        if offset < size:
            read_bytes = block_size
        else:
            read_bytes = size - offset

        encrypted_bytes = GetManyBytes(read_encrypt_address, read_bytes)
        f_enc_dump.write(encrypted_bytes)
        read_encrypt_address = read_encrypt_address + padding + read_bytes

    f_enc_dump.close()


def dump_decrypt_data(file_encrypt_name, file_decrypt_name, key_value, size):
    f_enc_dump = open(file_encrypt_name, "rb")
    f_dec_dump = open(file_decrypt_name, "wb")

    enc_bytes = f_enc_dump.read(size)

    for i in range(0, size, 4):
        int_data = bytes_to_int(enc_bytes,i)

        int_data += i
        int_data ^= (key_value + i)

        f_dec_dump.write(chr(int_data & 0x000000ff))
        f_dec_dump.write(chr((int_data >> 8) & 0x000000ff))
        f_dec_dump.write(chr((int_data >> 16) & 0x000000ff))
        f_dec_dump.write(chr((int_data >> 24) & 0x000000ff))

    f_enc_dump.close()
    f_dec_dump.close()

def dump_decrypt_data2(file_encrypt_name, file_decrypt_name, key_value, offset):
    f_enc_dump = open(file_encrypt_name, "rb")
    f_dec_dump = open(file_decrypt_name, "wb")

    f_enc_dump.seek(offset, 0)
    size = bytes_to_int(f_enc_dump.read(4), 0)

    print str(size) + "\n"
    enc_bytes = f_enc_dump.read(size)

    for i in range(0, size, 4):
        int_data = bytes_to_int(enc_bytes,i)

        int_data += i
        int_data ^= (key_value + i)
        f_dec_dump.write(chr(int_data & 0x000000ff))
        f_dec_dump.write(chr((int_data >> 8) & 0x000000ff))
        f_dec_dump.write(chr((int_data >> 16) & 0x000000ff))
        f_dec_dump.write(chr((int_data >> 24) & 0x000000ff))

    f_enc_dump.close()
    f_dec_dump.close()

padding_size = 0
block_size = 0

entry_point = BeginEA()
# start with finding encrypted data address
tmp_address = get_specific_address(entry_point, entry_point + 0x300, "mov", 1, "RegQueryValueEx")

# finding sub_function to contain an encrypt data value
sub_func = GetOperandValue(get_specific_address(tmp_address, tmp_address + 0x10, "call", -1, ""), 0)

# try to get encrypt data
encrypted_offset = get_specific_address(sub_func + 0x80, sub_func + 0x100, "mov", 1, "offset")
if encrypted_offset == 0:
    # try to get encrypt data with other way
    encrypted_offset = get_specific_address(sub_func + 0x80, sub_func + 0x100, "lea", 1, "dword_")

encrypted_address = GetOperandValue(encrypted_offset, 1)
encrypted_data = GetString(encrypted_address)

# if can't get string data, try to move address
if encrypted_data == None:
    encrypted_address += 4

# get encrypted data size
size = Dword(encrypted_address - 4)

print "encrypted data address %x" % encrypted_address
print "encrypted size : %x" % size

# start with finding padding size
tmp_value = ""

while True:
    tmp_address = get_specific_address(tmp_address, tmp_address + 0x30, "mov", 0, "dword_")
    tmp_value = GetOpnd(tmp_address, 1)

    if tmp_value not in ["eax", "ecx", "edx", "ebx", "esp", "ebp"]:
        padding_size = int(re.search(r'[A-F0-9]+', tmp_value).group(), 16)

        if padding_size != 0:
            break

print "padding data address %x" % tmp_address
print "padding size : %x" % padding_size

# start with finding block size
while True:
    tmp_address = get_specific_address(tmp_address, tmp_address + 0x30, "mov", 1, "dword_")
    block_size = Dword(GetOperandValue(tmp_address, 1))

    if block_size != 0:
        break

print "block data address %x" % tmp_address
print "block size : %x" % block_size

# make encrypted dump file without padding
dump_encrypt_data("encrypt_dump.bin", encrypted_address, size, block_size, padding_size)
# start with finding decryption key
tmp_value = ""
# try to find push command address with integer value like "sub_function(number, number)"
while True:
    tmp_address = get_specific_address(tmp_address + 0x50, tmp_address + 0x300, "push", -1, "")
    tmp_value = GetOpnd(tmp_address, 0)
    # to skip opcodes like push eax, push ecx, etc...
    if tmp_value not in ["eax", "ecx", "edx", "ebx", "esp", "ebp"]:
        break

# find a sub function that have decryption key
sub_func = GetOperandValue(get_specific_address(tmp_address, tmp_address + 0x300, "call", -1, ""), 0)
# find an address that contains a key value. normally key is included in "lea eax+edx+key"
key_address = get_specific_address(sub_func, sub_func + 0x300, "lea", 1, "eax+edx")

# Get decrypt key value and add 2
key_value = int(re.search(r'[A-F0-9]+', GetOpnd(key_address, 1)).group(), 16) + 2

print "decrypt key address %x" % key_address
print "decrypt key value %x" % key_value

# create a dump file with decrypted data
dump_decrypt_data("encrypt_dump.bin", "decrypt_dump.bin", key_value, size)

# create a decrypted file
# normally key is 0x3E9
# normally the offset included encryption data is 0x120
dump_decrypt_data2("decrypt_dump.bin", "unpack_dump.bin", 0x3E9, 0x120)
