# A basic fcatalog client (For IDA)
# By xorpd.

import logging
import socket
import struct
import collections


class FCatalogClientError(Exception): pass
class DeserializeError(FCatalogClientError): pass
class SerializeError(FCatalogClientError): pass
class NetError(FCatalogClientError): pass
class DBEndpointError(FCatalogClientError): pass

logger = logging.getLogger(__name__)

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
    returns (dword,msg)
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
    msg = dword_pack(MsgTypes.CHOOSE_DB,inner_msg)
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
    We assume that msg does not contain the message type package.
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


# An abstract class for FrameEndpoint:
class FrameEndpoint(object):
    def send_frame(self,data):
        """Send a frame to remote host"""
        raise NotImplementedError()
    def recv_frame(self):
        """Receive a frame from remote import host"""
        raise NotImplementedError()
    def close(self):
        """Close connection to remote host"""
        raise NotImplementedError()


class TCPFrameClient(FrameEndpoint):
    def __init__(self,remote):
        try:
            self._sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self._sock.connect(remote)
        except socket.error as e:
            raise NetError('Connection to remote host failed.')
            # raise NetError('Connection to remote host failed.') from e

    def send_frame(self,data):
        """
        Send one frame to a socket.
        """
        try:
            self._sock.sendall(len_prefix_pack(data))
        except socket.error as e:
            raise NetError('Failed sending a frame')
            # raise NetError('Failed sending a frame') from e

    def _recv_all(self,length):
        """
        Keep waiting for bytes until <length> bytes were received.
        Then return those <length> bytes.

        If connection was closed, return None.
        If connection was closed in the middle of receiving length bytes, raise
        a NetError exception.
        """
        # A list to keep the data we have received so far:
        data_l = []
        bytes_received = 0

        while bytes_received < length:
            try:
                data_received = self._sock.recv(length - bytes_received)
            except socket.error:
                raise NetError('Error receiving data')
            if len(data_received) == 0:
                # Remote host has disconnected:
                if bytes_received == 0:
                    return None
                raise NetError('Remote host closed in a middle of recv_all')
            bytes_received += len(data_received)
            data_l.append(data_received)

        # Combine all chunks of data received, and return them as one buffer:
        return "".join(data_l)


    def recv_frame(self):
        """
        Get one frame from a blocking tcp socket.
        Every frame is prefixed with a dword of its length.
        """
        # Receive 4 bytes:
        len_data = self._recv_all(4)

        if len_data is None:
            # Remote host has closed the connection:
            self.close()
            return None

        len_int = struct.unpack('I',len_data)[0]


        if len_int < 4:
            raise NetError('Received invalid frame from remote host')

        return self._recv_all(len_int)

    def close(self):
        """
        Close the FrameEndpoint.
        """
        # Do nothing if the socket is None. (Maybe we have already closed?)
        if self._sock is None:
            return

        try:
            self._sock.close()
            self._sock = None
        except socket.error:
            # We don't care about errors at this point.
            pass



class DBEndpoint(object):
    def __init__(self,frame_endpoint,db_name):
        # Initialize _sock to be None:
        self._sock = None

        # Keep remote: A tuple of address and port.
        self._frame_endpoint = frame_endpoint

        # Keep db_name:
        self._db_name = db_name

        # Send a choose_db frame:
        self._send_choose_db(self._db_name)

    def close(self):
        """
        Close connection to remote db.
        """
        self._frame_endpoint.close()

    def _send_choose_db(self,db_name):
        """
        Send a CHOOSE_DB message
        """
        self._frame_endpoint.send_frame(build_msg_choose_db(db_name))


    def add_function(self,func_name,func_comment,func_data):
        """
        Add a function to remote database.
        """
        logger.info('add_function {}'.format(func_name))
        self._frame_endpoint.send_frame(\
            build_msg_add_function(func_name,func_comment,func_data) \
            )

    def request_similars(self,func_data,num_similars):
        """
        Send a request for similar functions to remote db.
        Does not return any value. Use response_similars method to get the
        response from the server.
        """
        self._frame_endpoint.send_frame(\
            build_msg_get_similars(func_data,num_similars) \
            )

    def response_similars(self):
        """
        Get back a ResponseSimilars packet. We should have sent a
        RequestSimilars packet previously, or else this function might wait
        forever.
        returns a list of results, each of the form FSimilar.
        """
        # Wait for result from RequestSimilars query:
        frame = self._frame_endpoint.recv_frame()
        if frame is None:
            raise DBEndpointError('Remote host has closed the connection')

        msg_type, msg = dword_unpack(frame)
        if msg_type != MsgTypes.RESPONSE_SIMILARS:
            raise DBEndpointError('Invalid msg_type returned from server')

        similars = parse_msg_response_similars(msg)
        # if len(similars) > num_similars:
        #     raise DBEndpointError('Amount of results exceeded requested '
        #             ' num_similars')

        return similars


