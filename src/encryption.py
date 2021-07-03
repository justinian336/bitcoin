import hashlib
from hashlib import sha256
import hmac
from random import randint
from src.algebra import Point, FieldElement
from src.constants import *


def hash256(content):
    content = sha256(content)
    content = sha256(content.digest()).digest()
    return content


def encode_base58(s: bytes):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1'*count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])


def hash160(s):
    return hashlib.new('ripemd160', sha256(s).digest()).digest()


class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self**((P + 1)//4)

    @classmethod
    def parse(cls, sec_bin):
        """
        Parse a serialized point.
        """
        # Uncompressed SEC was used
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        # This is the right side of the S256 curve.
        y_prime = (x**3 + S256Field(B)).sqrt()
        # There are two Y for a given X in the curve, let's find out which one is it
        # The Y we're searching for is the even one if `is_even`, and the odd one otherwise.
        # There are two candidates: y_prime and P - y_prime
        # Because P is prime, P - y_prime is even if y_prime is odd, and viceversa. Use that
        # to find the right Y and return that point.
        if y_prime.num % 2 == 0:
            even_y = y_prime
            odd_y = S256Field(P - y_prime.num)
        else:
            even_y = S256Field(P - y_prime.num)
            odd_y = y_prime
        if is_even:
            return S256Point(x, even_y)
        else:
            return S256Point(x, odd_y)


class S256Point(Point):

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z, sig):
        s_inv = pow(sig.s, N-2, N)
        u = z*s_inv % N
        v = sig.r*s_inv % N
        total = u*G + v*self
        return total.x.num == sig.r

    # SEC-encode the point
    def sec(self, compressed=True):
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    # Steps to form a bitcoin address:
    # 1- Prefix: (0x00 for mainnet, 0x6f for testnet)
    # 2- SEC encoding -> sha256 -> ripemd160
    # 3- Combine 1 and 2
    # 4- hash256 of 3, then take the first 4 bytes (checksum)
    # 5- Combine 3 and 4 and base58-encode the result
    def address(self, compressed=True, testnet=False):
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        h160 = self.hash160(compressed)
        return encode_base58_checksum(prefix + h160)


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)


class Signature(object):

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return f'Signature({self.r},{self.s})'

    # Encode
    def der(self):
        # Encode r into binary
        rbin = self.r.to_bytes(32, 'big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin

        # Marker of r (02) + length(r) + r
        result = bytes([2, len(rbin)]) + rbin

        # Encode s into binary
        sbin = self.s.to_bytes(32, 'big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin

        # Marker for s value (02) + length(s) + s
        result += bytes([2, len(sbin)]) + sbin

        # Marker for signature (30) + length(signature) + signature
        return bytes([0x30, len(result)]) + result


class PrivateKey(object):

    def __init__(self, secret):
        self.secret = secret
        self.point = secret*G

    def hex(self):
        return f'{self.secret}'.zfill(64)

    def sign(self, z, deterministic=False):
        if deterministic:
            k = self.deterministic_k(z)
        else:
            k = randint(0, N)
        r = (k*G).x.num
        k_inv = pow(k, N-2, N)
        s = (z + r*self.secret)*k_inv % N
        if s > N/2:
            s = N - s
        return Signature(r, s)

    # Obtain some `k` that is deterministic for a given z.
    # Good for reproducibility and testing
    def deterministic_k(self, z):
        k = b'\x00'*32
        v = b'\x01'*32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        k = hmac.new(
            k,
            v + b'\x00'+secret_bytes+z_bytes,
            sha256
        ).digest()
        v = hmac.new(k, v, sha256).digest()
        k = hmac.new(
            k,
            v + b'\x01'+secret_bytes+z_bytes,
            sha256
        ).digest()
        v = hmac.new(k, v, sha256).digest()

        while True:
            v = hmac.new(k, v, sha256).digest()
            candidate = int.from_bytes(v, 'big')
            if 1 <= candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', sha256).digest()
            v = hmac.new(k, v, sha256).digest()

    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'

        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''

        return encode_base58_checksum(prefix + secret_bytes + suffix)


# ECDSA
# The discrete log problem can be represented by:
# P = e*G
# If you know e, you can solve for P. But knowing P and G is not enough to solve for e.
# P: the public key (another point the Bitcoin Curve)
# e: the private key
# G: the S256Point
# Take a random number `k`, and define:
# k*G = R
# Where R is the resulting random point. We only care about the `x` coordinate of `R`, called `r`.
# Take some numbers `u` and `v`, and define:
# u*G + v*P = k*G
# Where u and v are not zero and can be chosen by the signer. Then:
# u*G + v*P = k*G implies v*P = (k - u)*G
# P = ((k- u)/v)G
# e = (k - u)/v
# Without knowing e, if u*G + v+P = k*G can be solved with some (u, v), then e = (k-u)/v would solve
# P = eG
# Since this would mean breaking the discrete log problem, which is extremely hard, we assume that
# whoever has (u, v) that solves that also knows e.
# Define:
# u = z/s, v = r/s, z = signature hash
# Then the signature algorithm is given by:
# s = (z + re)/k

# Whole verification process:
# We are given (r, s) as the signature, z as the hash, P as the public key (point) of the signer.
# Calculate u = z/s, v = r/s
# Calculate uG + vP = R
# Check that R.x == r

# Signature process:
# We are given z and know e, such that eG = P
# Choose a random k
# Calculate R = kG, define r = R.x
# Calculate s = (z + re)/k
# Return (r, s)