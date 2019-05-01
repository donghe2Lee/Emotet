from idc import *
from idautils import *
from idaapi import *

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

def get_arguments_cnt(_address):
    cnt = 0
    pre_address = _address

    while GetMnem(pre_address) in ["mov", "push"]:
        cnt += 1
        pre_address = PrevHead(pre_address)

    return cnt

def patch_all_encode_to_decode(_decode_function_address):

    for address in CodeRefsTo(_decode_function_address, 0):
        offset = 0
        key = 0
        cnt = 0

        pre_addr = PrevHead(address)

        for i in range(0, 10):
            if cnt == 2:
                break
            if argc == 3:
                if GetMnem(pre_addr) == "push":
                    cnt += 1
                    key = GetOperandValue(pre_addr, 0)

            elif argc == 2:
                if (GetMnem(pre_addr) == "mov" and "edx" in GetOpnd(pre_addr, 0)):
                    cnt += 1
                    key = GetOperandValue(pre_addr, 1)

            if GetMnem(pre_addr) == "mov" and "ecx" in GetOpnd(pre_addr, 0):
                cnt += 1
                offset = GetOperandValue(pre_addr, 1)

            pre_addr = PrevHead(pre_addr)

        if cnt == 2 and offset != 0:
            print "called decode_function at %x" % address
            print "decode data address %x" % offset
            print "decode key %x" % key

            while(Byte(offset) != 0):
                intLL = Byte(offset)
                intLH = Byte(offset+1) << 8
                intHL = Byte(offset+2) << 16
                intHH = Byte(offset+3) << 24

                int_data = intLL | intLH | intHL | intHH
                int_decode = int_data ^ key
                PatchByte(offset, (int_decode & 0x000000ff))
                PatchByte(offset + 1, (int_decode >> 8 & 0x000000ff))
                PatchByte(offset + 2, (int_decode >> 16 & 0x000000ff))
                PatchByte(offset + 3, (int_decode >> 24 & 0x000000ff))
                offset += 4

            print "patch encode data to decode data"
        else:
            print "patch failed"

seek_address = BeginEA()
text_st_address = get_segm_by_name(".text").startEA
text_ed_address = get_segm_by_name(".text").endEA

print "section start address: %x" % text_st_address
print "section end address: %x" % text_ed_address

# try to find a function address that decode data
offset = get_specific_address(seek_address + 0x50, text_ed_address, "mov", 1, "unk_")
decode_function_address = GetOperandValue(get_specific_address(offset, text_ed_address, "call", -1, ""), 0)

print "offset address: %x" % offset
print "decode function address: %x" % decode_function_address

# there are two type of functions that decode data with arguments
argc = get_arguments_cnt(offset)

print "decode function arguments would be....%x" % argc

patch_all_encode_to_decode(decode_function_address)
