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


        # A three somewhat similar functions:
        func_name1 = 'func_name1'
        func_comment1 = 'func_comment1'
        func_data1 = '230948509238459238459283409582309458230945'

        func_name2 = 'func_name2'
        func_comment2 = 'func_comment2'
        func_data2 = '230948509218459238459223409582309458230945'

        func_name3 = 'func_name3'
        func_comment3 = 'func_comment3'
        func_data3 = '230948509018459238459223409280309458030945'

        # A very different function:
        func_name4 = 'func_name4'
        func_comment4 = 'func_comment4'
        func_data4 = 'kasjflkasjfdlkasjdfoiuweoriuqwioreuwqioekaskldfjaslk'

        dbe.add_function(func_name1,func_comment1,func_data1)
        dbe.add_function(func_name2,func_comment2,func_data2)
        dbe.add_function(func_name3,func_comment3,func_data3)
        dbe.add_function(func_name4,func_comment4,func_data4)

        # Check if the amount of returned functions is reasonable:
        similars = dbe.request_similars(func_data1,1)
        self.assertEqual(len(similars),1)
        similars = dbe.request_similars(func_data1,2)
        self.assertEqual(len(similars),2)
        similars = dbe.request_similars(func_data1,3)
        self.assertEqual(len(similars),3)
        similars = dbe.request_similars(func_data1,4)
        self.assertEqual(len(similars),3)

        self.assertEqual(similars[0].name,func_name1)
        self.assertEqual(similars[0].comment,func_comment1)
        self.assertEqual(similars[0].sim_grade,NUM_HASHES)

        # Function 2 is second place with respect to similarity to function 1:
        self.assertEqual(similars[1].name,func_name2)
        self.assertLess(similars[1].sim_grade,NUM_HASHES)
        # Function 3 is third place:
        self.assertEqual(similars[2].name,func_name3)
        self.assertLess(similars[2].sim_grade,NUM_HASHES)

        # function 4 is the only function that looks like function 4 in this
        # dataset:
        similars = dbe.request_similars(func_data4,3)
        self.assertEqual(len(similars),1)
        self.assertEqual(similars[0].name,func_name4)

        dbe.close()


        # Check persistency of the database by opening the same one again and
        # running a query:
        frame_endpoint = TCPFrameClient(remote)
        dbe = DBEndpoint(frame_endpoint,db_name)

        similars = dbe.request_similars(func_data1,4)
        self.assertEqual(len(similars),3)

        self.assertEqual(similars[0].name,func_name1)
        self.assertEqual(similars[0].comment,func_comment1)
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






