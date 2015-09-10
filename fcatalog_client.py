# A basic fcatalog client (For IDA)
# By xorpd.

import socket
import idaapi
import struct
import collections


class FCatalogClientError(Exception): pass
class DeserializeError(FCatalogClientError): pass
class SerializeError(FCatalogClientError): pass
class NetError(FCatalogClientError): pass
class DBContextError(FcatalogClientError): pass


# The possible messages for the protocol:
class MsgTypes:
    CHOOSE_DB = 0
    ADD_FUNCTION = 1
    REQUEST_SIMILARS = 2
    RESPONSE_SIMILARS = 3


# A similar function struct
FSimilar = collections.namedtuple('FSimilar',\
        ['name','comment','sim_grade'])

############################################

def len_prefix_pack(msg):
    """
    Add a length prefix to a message
    """
    return struct.pack('I',len(msg)) + msg

def len_prefix_unpack(data):
    """
    Unpack a message with a length prefix.
    Returns msg , rest_of_data
    """
    if len(data) < 4:
        raise DeserializeError('data is too short to contain a length prefix')
    length = struct.unpack('I',data[0:4])[0]

    if 4 + length > len(data):
        raise DeserializeError('length prefix is invalid')


    # Return msg, rest of data:
    return data[4:4+length],data[4+length:]


def dword_pack(dword,msg):
    """
    Pack a buffer with a dword (4 bytes) prefix.
    """
    return struct.pack('I',dword) + msg

def dword_unpack(data):
    """
    Unpack a message with a length prefix.
    returns (msg_type,msg)
    """
    if len(data) < 4:
        raise DeserializeError('data is too short to contain a message type')
    dword = struct.unpack('I',data[0:4])[0]

    return dword,data[4:]

############################################################


def build_msg_choose_db(db_name):
    """
    Build a CHOOSE_DB message with the given db_name.
    """
    inner_msg = len_prefix_pack(db_name)
    msg = msg_type_pack(MsgTypes.CHOOSE_DB,inner_msg)
    return msg


def build_msg_add_function(func_name,func_comment,func_data):
    """
    Build an ADD_FUNCTION message with the given arguments.
    """
    ls = []
    ls.append(len_prefix_pack(func_name))
    ls.append(len_prefix_pack(func_comment))
    ls.append(len_prefix_pack(func_data))
    inner_msg = ''.join(ls)
    msg = dword_pack(MsgTypes.ADD_FUNCTION,inner_msg)
    return msg


def build_msg_get_similars(func_data,num_similars):
    """
    Build a REQUEST_SIMILARS message with the given arguments.
    """
    ls = [] 
    ls.append(len_prefix_pack(func_data))
    ls.append(struct.pack('I',num_similars))
    inner_msg = ''.join(ls)
    msg = dword_pack(MsgTypes.REQUEST_SIMILARS,inner_msg)
    return msg


def parse_msg_response_similars(msg):
    """
    Parse a response similars messages. Raise an exception if failed.
    """

    if len(msg) < 4:
        raise DeserializeError('RESPONSE_SIMILARS message is too short.')

    # Prepare list of results:
    res = []

    num_sims,msg = dword_unpack(msg)

    for _ in range(num_sims):

        name,msg = len_prefix_unpack(msg)
        comment,msg = len_prefix_unpack(msg)
        sim_grade,msg = dword_unpack(msg)

        # Build an FSimilar namedtuple:
        res.append(FSimilar(\
                name=name,comment=comment,sim_grade=sim_grade \
                ))

    # Return a list of FSimilars:
    return res


##############################################################

# See http://preshing.com/20110920/the-python-with-statement-by-example/
# For explanation about the with statement.

# TODO: Continue here.

class FrameEndpoint(object):
    def send_frame(self,data):
        """
        Send one frame to a socket.
        """
        try:
            self._sock.send(len_prefix_pack(data))
        except socket.error:
            raise NetError('Failed sending a frame')

    def recv_frame(self):
        """
        Get one frame from a blocking tcp socket.
        Every frame is prefixed with a dword of its length.
        """
        # Receive 4 bytes:
        try:
            len_data = self._sock.recv(4)
        except socket.error:
            raise NetError('Failed receiving a frame')

        if len(len_data) < 4:
            raise NetError('Received invalid frame from remote host')

    def close():
        pass

assert False

class DBContext(object):
    def __init__(self,remote,db_name):
        # Initialize _sock to be None:
        self._sock = None

        # Keep remote: A tuple of address and port.
        self._remote = remote

        # Keep db_name:
        self._db_name = db_name

    def __enter__(self):
        # Connect socket

        self._send_choose_db(self._db_name)
        # Handle exceptions here:
        assert False

    def __leave__(self):
        pass


    def _send_choose_db(self,db_name):
        """Send a CHOOSE_DB message"""
        self._send_frame(build_msg_choose_db(db_name))

    def add_function(self):
        pass

    def request_similars(self):
        pass


class FCatalogClient(object):
    def __init__(self):
        pass






