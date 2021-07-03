import hashlib
from hashlib import sha256
import hmac
from random import randint


class FieldElement(object):

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime - 1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f'FieldElement_{self.prime}({self.num})'

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields.')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields.')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, power, modulo=None):
        num = self.num.__pow__(power, self.prime)
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields.')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields.')
        num = self * (other**(self.prime - 2))
        return num


class Point(object):

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        if self.x is None and self.y is None:
            return

        if self.y**2 != self.x**3 + a*x + b:
            raise ValueError(f'({x}, {y}) is not on the curve')

    def __eq__(self, other):
        return all([
            self.x == other.x and self.y == other.y,
            self.a == other.a and self.b == other.b
            ]
        )

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')

        if self.x is None:
            return other

        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        if self == other and self.y == FieldElement(0, self.y.prime):
            return self.__class__(None, None, self.a, self.b)

        if self == other:
            slope = (FieldElement(3, self.x.prime)*self.x**2 + self.a)/(FieldElement(2, self.y.prime)*self.y)
            x3 = slope**2 - FieldElement(2, self.x.prime)*self.x
            y3 = slope*(self.x - x3) - self.y
            return self.__class__(x3, y3, self.a, self.b)

        else:
            slope = (other.y - self.y)/(other.x - self.x)
            x3 = slope**2 - self.x - other.x
            y3 = slope*(self.x - x3) - self.y
            return self.__class__(x3, y3, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result
