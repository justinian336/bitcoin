import unittest
from src.encryption import *


class FieldAlgebraTest(unittest.TestCase):
    def test_on_curve(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        for x_raw, y_raw in valid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            Point(x, y, a, b)
        for x_raw, y_raw in invalid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)

    def test_point_addition(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        x1 = FieldElement(192, prime)
        y1 = FieldElement(105, prime)
        x2 = FieldElement(17, prime)
        y2 = FieldElement(56, prime)
        p1 = Point(x1, y1, a, b)
        p2 = Point(x2, y2, a, b)
        p3 = p1 + p2
        assert p3.x == FieldElement(170, prime)
        assert p3.y == FieldElement(142, prime)

    def test_correct_signature_compressed_mainnet(self):
        secret = 0x12345deadbeef
        private_key = PrivateKey(secret)
        address = private_key.point.address(compressed=True, testnet=False)
        assert address == '1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1'

    def test_correct_signature_uncompressed_testnet(self):
        secret = 5002
        private_key = PrivateKey(secret)
        address = private_key.point.address(compressed=False, testnet=True)
        assert address == 'mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA'

    def test_correct_signature_compressed_testnet(self):
        secret = 2020**5
        private_key = PrivateKey(secret)
        address = private_key.point.address(compressed=True, testnet=True)
        assert address == 'mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH'


if __name__ == '__main__':
    unittest.main()
