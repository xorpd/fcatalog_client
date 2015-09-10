import unittest

class TestWithStatementException(unittest.TestCase):
    def test_exception_caught(self):
        """
        Test if the python with statement executes __exit__ even if an
        exception happens in the middle.
        """
        l = []
        class CContext(object):
            def __enter__(self):
                l.append('enter')

            def __exit__(self,type,value,traceback):
                l.append('exit')

            def ex_method(self):
                """A method that raises an exception"""
                raise Exception()

        try:
            with CContext() as c:
                pass
        except Exception:
            pass

        self.assertEqual(l,['enter','exit'])

