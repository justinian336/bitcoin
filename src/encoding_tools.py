"""
Some serialization tools
"""

def little_endian_to_int(b: bytes):
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int):
    return n.to_bytes(length, 'little')


def read_varint(s):
    # Read the first byte as an int. This tells us whether to read 1, 2, 4 or 8 bytes.
    i = s.read(1)[0]
    # Read 2 bytes
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    # Read 4 bytes
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    # Read 8 bytes
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    # Just return the number (assumes it is 1 byte only? could be larger...)
    else:
        return i


def encode_varint(i):
    # Check if the number is under 256 (can be encoded in 1 byte)
    if i < 2**8:
        return bytes([i])
    # Under 2 bytes
    elif i < 2**(8*2):
        return b'\xfd' + int_to_little_endian(i, 2)
    # Under 4 bytes
    elif i < 2**(8*4):
        return b'\xfe' + int_to_little_endian(i, 4)
    # Under 8 bytes
    elif i < 2**(8*8):
        return b'\xff' + int_to_little_endian(i, 8)
    # NOPE
    else:
        raise ValueError(
            f'Value too large to encode: {i}'
        )