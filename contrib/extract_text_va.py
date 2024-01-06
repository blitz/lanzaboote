import pefile
import sys

target = sys.argv[1]
t_section = sys.argv if len(sys.argv) > 2 else ".text"
pe = pefile.PE(target, fast_load=True)

for section in pe.sections:
    if section.Name.decode('ascii').rstrip('\x00') == t_section:
        print(hex(section.VirtualAddress))
