# A basic fcatalog client (For IDA)
# By xorpd.

import idaapi
import struct

class ExceptFCatalogClient(Exception): pass
class ExceptMsg(ExceptFCatalogClient): pass

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
        raise ExceptMsg('data is too short to contain a length prefix')
    length = struct.unpack('I',data[0:4])[0]

    if 4 + length != len(data):
        raise ExceptMsg('length prefix is invalid')

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
        raise ExceptMsg('data is too short to contain a message type')
    msg_type = struct.unpack('I',data[0:4])[0]

    return msg_type,data[4:]



def build_msg_choose_db(db_name):
    """
    Build a CHOOSE_DB message with the given db_name.
    """
    inner_msg = len_prefix_pack(db_name)
    msg = msg_type_pack(MsgTypes.CHOOSE_DB,inner_msg)
    data = len_prefix_pack(msg)
    return data


def build_msg_add_function(func_name,func_comment,func_data):
    """
    Build a ADD_FUNCTION message with the given arguments.
    """

    pass


def build_msg_get_similars(func_data,num_similars):
    pass



class FCatalogClient(object):
    def __init__(self):
        pass





