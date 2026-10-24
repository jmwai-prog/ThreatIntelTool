import unittest

from validators import IoCType, ValidationError, classify_ioc

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class ValidatorTests(unittest.TestCase):
    def test_valid_inputs(self):
        self.assertEqual(classify_ioc("8.8.8.8").ioc_type, IoCType.IPV4)
        self.assertEqual(classify_ioc("Example.COM").value, "example.com")
        self.assertEqual(classify_ioc("evil[.]example[.]org").value, "evil.example.org")
        self.assertEqual(classify_ioc(EICAR.upper()).value, EICAR)
        self.assertEqual(classify_ioc(" xn--bcher-kva.com ").ioc_type, IoCType.DOMAIN)

    def test_rejects_malformed_and_hostile_input(self):
        bad = [
            "", "   ", "256.1.1.1", "01.1.1.1", "1.2.3", "8.8.8.8; DROP TABLE x",
            "-bad.com", "bad-.com", "a..com", "localhost", "host.local",
            "http://example.com", "exa mple.com", "x" * 400, "8.8.8.8\n1.1.1.1",
            "e\u0455xample.com", "\x1b[31mred.com", EICAR[:-1], "z" * 64,
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    classify_ioc(value)

    def test_private_and_reserved_ips_rejected(self):
        for value in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    classify_ioc(value)

    def test_weaker_hashes_rejected(self):
        with self.assertRaises(ValidationError):
            classify_ioc("d41d8cd98f00b204e9800998ecf8427e")


if __name__ == "__main__":
    unittest.main()