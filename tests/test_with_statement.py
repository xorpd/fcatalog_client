from __future__ import with_statement
import unittest

class TestWithStatementException(unittest.TestCase):
    def test_exception_caught(self):
        l = []
        class CContext(object):
            def __enter__(self):
                l.append(0)
                assert False

            def __leave__(self):
                l.append(1)

            def ex_method(self):
                """A method that raises an exception"""
                raise Exception()

        try:
            with CContext() as c:
                pass
        except Exception:
            pass

        self.assertEqual(l,[0,1])

