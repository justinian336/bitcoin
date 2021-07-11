"""
Implementing some Script operations.
Script is a non Turing-complete language for programming Bitcoin smart contracts.
Smart contracts are basically a sequence operations and elements (data), and a stack.
Some information on the available Ops can be found in:
https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
For simplification, the ops implemented here attempt an operation on the stack, and
return True in case of success or False otherwise.
There's quite a lot of opcodes to implement, so I'll just go for some common ones
"""

from src.encryption import hash256, hash160, S256Field, Signature


def encode_num(num):
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8

    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80

    return bytes(result)


def decode_num(element):
    if element == b'':
        return 0
    big_endian = element[::-1]

    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]

    for c in big_endian[1:]:
        result <<= 8
        result += c

    if negative:
        return -result
    else:
        return result


def op_0(stack):
    stack.append(encode_num(0))
    return True




# Duplicate the last element in the stack
def op_dup(stack):
    if len(stack) < 1:
        return False
    else:
        stack.append(stack[-1])
        return True


# Apply hash256 to the last element in the stack
def op_hash256(stack):
    if len(stack) < 1:
        return False
    else:
        element = stack.pop()
        stack.append(hash256(element))
        return True


def op_hash160(stack):
    # Could refactor this check into a decorator
    if len(stack) < 1:
        return False
    else:
        element = stack.pop()
        stack.append(hash160(element))
        return True


def op_checksig(stack: list, z):
    if len(stack) < 2:
        return False
    else:
        #Extract the public key and the signature from the stack
        signature = stack.pop(0)
        pubkey = stack.pop(0)
        # Parse the pubkey
        sec = S256Field.parse(pubkey)
        # Parse the signature
        sig = Signature.parse(signature[:-1])
        # Verify the signature
        is_verified = sec.verify(z, sig)
        if is_verified:
            stack.append(encode_num(1))
            return True
        else:
            op_0(stack)
            return False


OP_CODE_FUNCTIONS = {
    118: op_dup,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig
}