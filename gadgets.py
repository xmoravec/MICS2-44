import sys
from capstone import *
import binascii

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

##############################################################
# takes a string of arbitrary length and formats it 0x for Capstone
def convertXCS(s):
    if len(s) < 2: 
        print "Input too short!"
        return 0
    
    if len(s) % 2 != 0:
        print "Input must be multiple of 2!"
        return 0

    conX = ''
    
    for i in range(0, len(s), 2):
        b = s[i:i+2]
        b = chr(int(b, 16))
        conX = conX + b
    return conX


##############################################################


def getHexStreamsFromElfExecutableSections(filename):
    print "Processing file:", filename
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        
        execSections = []
        goodSections = [".text"] #[".interp", ".note.ABI-tag", ".note.gnu.build-id", ".gnu.hash", ".hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt", ".init", ".plt", ".text", ".fini", ".rodata", ".eh_frame_hdr", ".eh_frame"]
        checkedSections = [".init", ".plt", ".text", ".fini"]
        
        for nsec, section in enumerate(elffile.iter_sections()):

            # check if it is an executable section containing instructions
            
            # good sections we know so far:
            #.interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .text .fini .rodata .eh_frame_hdr .eh_frame
        
            if section.name not in goodSections:
                continue
            
            # add new executable section with the following information
            # - name
            # - address where the section is loaded in memory
            # - hexa string of the instructions
            name = section.name
            addr = section['sh_addr']
            byteStream = section.data()
            hexStream = binascii.hexlify(byteStream)
            newExecSection = {}
            newExecSection['name'] = name
            newExecSection['addr'] = addr
            newExecSection['hexStream'] = hexStream
            execSections.append(newExecSection)

        return execSections


branching_instructions = ["jne", "je", "jg", "jle", "jl", "jge"]

if __name__ == '__main__':
    if '--file' not in sys.argv:
        print("you must specify: --file followed by list of files to analyze")
    else:
        length = -1
        if "-length" in sys.argv:
            length = int(sys.argv[int(sys.argv.index("-length") + 1)])
        offset = 0
        if '--offset' in sys.argv:
            depth = int(sys.argv[int(sys.argv.index("--offset") + 1)])
        
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        for filename in sys.argv[sys.argv.index("--file") + 1:]:
            execSections = getHexStreamsFromElfExecutableSections(filename)
            print "Found ", len(execSections), " executable sections:"

            for i, section in enumerate(execSections):
                print "   ", i, ": ", section['name'], "0x", hex(section['addr']), #section['hexStream']
                depth = len(section['hexStream'])
                if '--depth' in sys.argv:
                    depth = int(sys.argv[int(sys.argv.index("--depth") + 1)])
                
                gadgets = md.disasm_lite(convertXCS(section['hexStream'][0:depth]), offset)
                unique_gadgets = []
                for address, size, mnemonic, op_str in gadgets:
                    if ((mnemonic, op_str) not in unique_gadgets) and (size == length + 1 or length == -1) and (mnemonic not in branching_instructions):
                        unique_gadgets.append((mnemonic, op_str))
                        if "--print" in sys.argv:
                            print "gadget: ", mnemonic, op_str

                print "Total unique gadgets: ",  len(unique_gadgets)
            
