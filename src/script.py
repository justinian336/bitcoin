"""
Implement Script, Bitcoin's smart contract language, as well as utility
functions for parsing and serializing them.
Implement also some standard scripts.
"""
from src.encoding_tools import *
from src.ops import OP_CODE_FUNCTIONS


# The abstract definition of scripts
class Script(object):

    def __init__(self, commands=None):
        self.commands = commands or []

    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        commands = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]

            # In this case it is an element of length n
            if 1 <= current_byte <= 75:
                n = current_byte
                # Add the element to the commands list
                commands.append(s.read(n))
                # Update the number of bytes read
                count += n
            # The following byte is the length of an element to be pushed (OP_PUSHDATA1)
            elif current_byte == 76:
                # The length of the element
                n_bytes = 1
                data_length = little_endian_to_int(s.read(n_bytes))
                commands.append(s.read(data_length))
                count += data_length + n_bytes
            # Same, but this time the length is encoded in two bytes (OP_PUSHDATA2)
            elif current_byte == 77:
                # The length of the element
                n_bytes = 2
                data_length = little_endian_to_int(s.read(n_bytes))
                commands.append(s.read(data_length))
                count += data_length + n_bytes
            # Same, but this time the length is encoded in four bytes (OP_PUSHDATA4)
            elif current_byte == 78:
                n_bytes = 4
                data_length = little_endian_to_int(s.read(n_bytes))
                commands.append(s.read(data_length))
                count += data_length + n_bytes
            else:
                op_code = current_byte
                commands.append(op_code)

        if count != length:
            raise SyntaxError('Failed trying to parse the script.')

        return cls(commands)

    # Serialize the script
    def raw_serialize(self):
        result = b''
        # Start from an empty byte string and append each command in order:
        for command in self.commands:
            # If it's an int, then it's an opcode, so just add it to the result
            if type(command) == int:
                result += int_to_little_endian(command, 1)
            else:
                # Otherwise it is the length of an element
                length = len(command)

                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif 75 < length < 2**8:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif 2**8 < length < 2**9:
                    result += int_to_little_endian(77, 2)
                    result += int_to_little_endian(length, 2)
                elif 2**9 < length < 2**11:
                    result += int_to_little_endian(77, 4)
                    result += int_to_little_endian(length, 4)
                else:
                    raise ValueError('Command is too long')
        return result

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z):
        commands = self.commands[:]
        stack = []
        altstack = []
        while len(commands) > 0:
            cmd = commands.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                # This would be much more elegant with pattern matching, this is lame...
                # These commands need the top element of the stack
                if cmd in (99, 100):
                    if not operation(stack, commands):
                        print(f'Bad OP: {cmd}')
                        return False

                # OPs that require an alternative stack
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        print(f'Bad OP: {cmd}')
                        return False

                # Require the signature hash
                elif cmd in (172, 173, 174, 175):
                    if not operation(stack, z):
                        print(f'Bad OP: {cmd}')
                        return False

                # OPs that only require the stack itself
                else:
                    if not operation(stack):
                        print(f'Bad OP: {cmd}')
                        return False

            # It's an element, so just append it to the stack
            else:
                stack.append(cmd)

        # Final check: the stack should not be empty, and the last element should not
        # be an empty byte string.
        if len(stack) == 0:
            return False
        if stack.pop(0) == b'':
            return False

        # All checks passed
        return True

    # Naive implementation. In reality the scripts wouldn't be merged this way for security purposes (?)
    def __add__(self, other):
        return Script(self.commands + other.commands)





