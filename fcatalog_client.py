# A basic fcatalog client (For IDA)
# By xorpd.

import idaapi
import struct

class FCatalogClientError(Exception): pass
class DeserializeError(FCatalogClientError): pass
class SerializeError(FCatalogClientError): pass

# The possible messages for the protocol:
class MsgTypes:
    CHOOSE_DB = 0
    ADD_FUNCTION = 1
    REQUEST_SIMILARS = 2
    RESPONSE_SIMILARS = 3

############################################

def len_prefix_pack(msg):
    """
    Add a length prefix to a message
    """
    return struct.pack('I',len(msg)) + msg

def len_prefix_unpack(data):
    """
    Unpack a message with a length prefix.
    """
    if len(data) < 4:
        raise DeserializeError('data is too short to contain a length prefix')
    length = struct.unpack('I',data[0:4])[0]

    if 4 + length != len(data):
        raise DeserializeError('length prefix is invalid')

    return data[4:]


def msg_type_pack(msg_type,msg):
    """
    Pack the message with a message type prefix.
    """
    return struct.pack('I',msg_type) + msg

def msg_type_unpack(data):
    """
    Unpack a message with a length prefix.
    returns (msg_type,msg)
    """
    if len(data) < 4:
        raise DeserializeError('data is too short to contain a message type')
    msg_type = struct.unpack('I',data[0:4])[0]

    return msg_type,data[4:]

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
    msg = msg_type_pack(MsgTypes.ADD_FUNCTION,inner_msg)
    return msg


def build_msg_get_similars(func_data,num_similars):
    """
    Build a REQUEST_SIMILARS message with the given arguments.
    """
    ls = [] 
    ls.append(len_prefix_pack(func_data))
    ls.append(struct.pack('I',num_similars))
    inner_msg = ''.join(ls)
    msg = msg_type_pack(MsgTypes.REQUEST_SIMILARS,inner_msg)
    return msg


def parse_msg_response_similars(msg):
    """
    Parse a response similars messages. Raise an exception if failed.
    """
    if len(msg) < 4:
        raise DeserializeError('RESPONSE_SIMILARS message is too short.')

    num_sims = struct.unpack('I',msg[0:4])[0]

    assert False

    pass

##############################################################

def get_frame(sock):
    """
    Get one frame from a blocking tcp socket.
    Every frame is prefixed with a dword of its length.
    """
    pass

def send_frame(sock):
    """
    Send one frame to a socket.
    """
    pass




class FCatalogClient(object):
    def __init__(self):
        pass





