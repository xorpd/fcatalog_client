import sys
import string
import random
from fcatalog_client import TCPFrameClient,DBEndpoint

def rand_db_name():
    """
    Generate a random test_db name.
    """
    rand_part = \
            ''.join(random.choice(string.ascii_lowercase) for _ in range(20))

    return 'test_db_' + rand_part


def live_test_client(remote):
    """
    Test the client against a remote server of address:port remote.
    """
    db_name = rand_db_name()

    frame_endpoint = TCPFrameClient(remote)
    dbe = DBEndpoint(frame_endpoint,db_name)

    dbe.close()



def start():
    if len(sys.argv) != 3:
        msg = ('This program tests the correctness of fcatalog client code'
               ' against a live server.')
        print('Usage {} address port'.format(sys.argv[0]))

    address = sys.argv[1]
    port = int(sys.argv[2])

    live_test_client((address,port))




if __name__ == '__main__':
    start()

