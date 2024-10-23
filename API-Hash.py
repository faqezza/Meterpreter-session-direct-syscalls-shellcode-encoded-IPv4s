def custom_hash(name):
    result = 0
    for char in name:
        result = ord(char) ^ result
        result = result * 0x1000193
    return result & 0xFFFFFFFF  # Limit to 32 bits

hash_get_proc_address = custom_hash("FindResourceA")
print(hex(hash_get_proc_address))  # Exibe o hash em hexadecimal
