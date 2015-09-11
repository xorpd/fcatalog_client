import unittest
import sys
import string
import random

from fcatalog_client.db_endpoint import TCPFrameClient,DBEndpoint


# Length of random part of db name:
RAND_PART_LENGTH = 20

# Amount of hashes used for the catalog1 signature.
NUM_HASHES = 16

# Address of remote server:
remote = None

def live_test_client():
    """
    Test the client against a remote server of address:port remote.
    """
    # See 
    # http://stackoverflow.com/questions/19087189/python-unittest-testcase-object-has-no-attribute-runtest
    # For more info.

    # suite = unittest.TestSuite()
    # Instantiate all tests and insert then into suite:
    tsuites = []
    for ts in tests_list:
        tsuites.append(\
                unittest.defaultTestLoader.loadTestsFromTestCase(ts)\
                )
    suite = unittest.TestSuite(tsuites)
    unittest.TextTestRunner().run(suite)


def rand_db_name():
    """
    Generate a random test_db name.
    """
    rand_part = \
            ''.join(random.choice(string.ascii_lowercase) for _ in \
            range(RAND_PART_LENGTH))

    return 'test_db_' + rand_part

###########################################################################


class TestRemoteDB(unittest.TestCase):
    def test_basic_db_function(self):
        # Get a random db name:
        db_name = rand_db_name()
        frame_endpoint = TCPFrameClient(remote)
        dbe = DBEndpoint(frame_endpoint,db_name)


        func_name = 'func_name1'
        func_comment = 'func_comment1'
        func_data = '230948509238459238459283409582309458230945'

        dbe.add_function(func_name,func_comment,func_data)
        similars = dbe.request_similars(func_data,3)
        self.assertEqual(len(similars),1)
        self.assertEqual(similars[0].name,func_name)
        self.assertEqual(similars[0].comment,func_comment)
        self.assertEqual(similars[0].sim_grade,NUM_HASHES)

        dbe.close()
        

tests_list = [TestRemoteDB]

############################################################################

if __name__ == '__main__':
    if len(sys.argv) != 3:
        msg = ('This program tests the correctness of fcatalog client code'
               ' against a live server.')
        print(msg)
        print('USAGE: {} address port'.format(sys.argv[0]))
        exit(2)

    address = sys.argv[1]
    port = int(sys.argv[2])

    # Set address of remote server:
    remote = (address,port)

    live_test_client()






