import unittest

from fcatalog_client.utils import blockify


class TestBlockify(unittest.TestCase):
    def test_blockify_7_3(self):
        """
        Make blocks of size 3 from a range of size 7.
        """
        res = []
        for b in blockify(range(7),3):
            res.append(b)

        assert res == [[0,1,2],[3,4,5],[6]]

    def test_blockify_9_3(self):
        """
        Test basic operation of blockify.
        """
        res = []
        for b in blockify(range(9),3):
            res.append(b)

        assert res == [[0,1,2],[3,4,5],[6,7,8]]

    def test_blockify_empty(self):
        """
        Try to blockify an empty iterator:
        """
        res = []
        for b in blockify(range(0),5):
            res.append(b)

        assert len(res) == 0
