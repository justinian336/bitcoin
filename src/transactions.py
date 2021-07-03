"""
Transactions have four components:
- Version (4 bytes int): the "version" of the protocol to use for processing.
  For an example when version 2 or higher is necessary see:
  https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
- Inputs[]: A list. Its length is encoded into the transaction as a varint of
  1, 2, 4 or 8 bytes. Each input contains:
    - Previous Transaction ID (hash256 of the previous transaction. 32 bytes little-endian)
    - Previous Transaction index (4 bytes little-endian)
    - ScriptSig: smart contract code. Variable length, preceded by its length as a varint.
    - Sequence (4 bytes little-endian)
- Outputs[]: A list. Its length is encoded into the transaction as a varint of
  1, 2, 4 or 8 bytes. Each output contains:
    - Amount (8 bytes, little-endian): expressed in satoshis (1/100,000,000th of a BTC)
    - ScriptPubKey: smart contract code. Variable length, preceded by its length as a varint.
- Locktime (4 bytes, little-endian): makes the transaction unspendable until a condition is met (block number or datetime).
  If under 500,000,000, it is a block number, otherwise it's a Unix timestamp. Ignored if the sequence
  for each Input is `ffffffff`
"""

from encryption import hash256


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


class Transaction(object):

    def __init__(self, version, inputs, outputs, locktime, testnet=False):
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
        self.testnet = testnet

    @classmethod
    def parse(cls, stream, testnet=False):
        # The version is 4 bytes
        version: int = little_endian_to_int(stream.read(4))
        # Get the number of inputs which is a varint
        n_inputs = read_varint(stream)
        # The inputs will be a list of TransactionInput
        inputs = []
        # Parse `n_inputs` TransactionInputs from the stream
        for _ in range(n_inputs):
            inputs.append(TransactionInput.parse(stream))
        # Read the number of outputs from the stream
        n_outputs = read_varint(stream)
        outputs = []
        # Read the outputs and append them into a list
        for _ in range(n_outputs):
            outputs.append(TransactionOutput.parse(stream))
        # Locktime is 4 bytes little-endian as int
        locktime: int = little_endian_to_int(stream.read(4))
        # Return a Transaction instance.
        return cls(version, inputs, outputs, locktime, testnet)

    def serialize(self) -> bytes:
        # Serialize the version as 4 bytes in little-endian
        serialized: bytes = int_to_little_endian(self.version, 4)
        # Add the number of inputs as a varint
        serialized += encode_varint(len(self.inputs))
        # Then add the inputs
        for inp in self.inputs:
            serialized += inp.serialize()
        # Now add the number of outputs as a varint
        serialized += encode_varint(len(self.outputs))
        # Then also add the outputs
        for out in self.outputs:
            serialized += out.serialize()
        # Finally add the locktime as 4 bytes little-endian.
        serialized += int_to_little_endian(self.locktime, 4)
        return serialized

    def hash(self):
        return hash256(self.serialize())[::-1]

    def id(self):
        return self.hash().hex()


class TransactionInput(object):

    def __init__(self, prev_transaction, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_transaction = prev_transaction
        self.prev_index = prev_index
        if script_sig is None:
            # TODO: define the Script class
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    @classmethod
    def parse(cls, s):
        # Previous transaction is 32 bytes little-endian (that's why we revert the bytes)
        prev_transaction: bytes = s.read(32)[::-1]
        # 4 bytes little-endian as int
        prev_index: int = little_endian_to_int(s.read(4))
        # Leave it to `Script`'s parse method (will be variable)
        script_sig: Script = Script.parse(s)
        # 4 bytes little-endian as int
        sequence: int = little_endian_to_int(s.read(4))
        # Return a TransactionInput instance
        return cls(prev_transaction, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        # Start by the previous transaction as little-endian (revert the bytes order)
        serialized: bytes = self.prev_transaction[::-1]
        # Add the previous index int as 4 bytes in little-endian
        serialized += int_to_little_endian(self.prev_index, 4)
        # Serialize the ScriptSig
        serialized += self.script_sig.serialize()
        # Serialize the sequence int as 4 bytes in little-endian
        serialized += int_to_little_endian(self.sequence, 4)
        return serialized


class TransactionOutput(object):

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def serialize(self) -> bytes:
        # The amount is 8 bytes little-endian
        serialized: bytes = int_to_little_endian(self.amount, 8)
        # Serialize the script_pubkey
        serialized += self.script_pubkey.serialize()
        return serialized

    @classmethod
    def parse(cls, s):
        amount: int = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)
