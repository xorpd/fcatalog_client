import unittest
import struct
import socket

from fcatalog_client.db_endpoint import \
    MsgTypes,\
    len_prefix_pack,len_prefix_unpack,dword_pack,dword_unpack,\
    build_msg_choose_db,build_msg_add_function,build_msg_get_similars,\
    parse_msg_response_similars,\
    TCPFrameClient


class TestPacking(unittest.TestCase):
    def test_len_prefix_pack(self):
        """
        Test len_prefix_{pack,unpack} functions.
        """
        # Simple packing and unpacking:
        msg = 'Example msg'
        data = len_prefix_pack(msg)
        self.assertEqual(len(data),len(msg) + 4)
        msg1,data1 = len_prefix_unpack(data)

        self.assertEqual(msg1,msg)
        self.assertEqual(len(data1),0)

        # Dealing with extra data:
        extra_data = 'some extra'
        longer_data = data + extra_data
        msg2,data2 = len_prefix_unpack(longer_data)
        self.assertEqual(msg2,msg)
        self.assertEqual(data2,extra_data)

    def test_dword_pack(self):
        """
        Test dword_{pack,unpack} functions.
        """
        msg = 'This is example msg'
        num = 0x1337
        data = dword_pack(num,msg)
        self.assertEqual(len(data),len(msg) + 4)
        num1,msg1 = dword_unpack(data)

        self.assertEqual(num1,num)
        self.assertEqual(msg1,msg)


class TestBuildMessages(unittest.TestCase):
    def test_build_msg_choose_db(self):
        db_name = 'my_db_name'
        data = build_msg_choose_db(db_name)
        msg_num, data = dword_unpack(data)

        self.assertEqual(msg_num,MsgTypes.CHOOSE_DB)
        self.assertEqual(struct.unpack('I',data[0:4])[0], len(db_name))
        self.assertEqual(data[4:],db_name)


    def test_build_msg_add_function(self):
        func_name = 'a_function_name'
        func_comment = 'A comment'
        func_data = 'klasdjflkasjdflkjasfkljasdfasdf'
        # Run build_msg_add_function on some strange arguments:
        data = build_msg_add_function(func_name,func_comment,func_data)

        # Build the data myself:
        res = ""
        for d in [func_name,func_comment,func_data]:
            res += struct.pack('I',len(d))
            res += d

        # Add message type:
        res = dword_pack(MsgTypes.ADD_FUNCTION,res)

        # Compare the two results:
        self.assertEqual(data,res)

    def test_build_msg_get_similars(self):
        func_data = 'kalsfdjaslkjfoiweuroiweurioweuriowjsdf'
        num_similars = 52
        # Run build_msg_get_similars with some arguments:
        data = build_msg_get_similars(func_data,num_similars)

        # Build the data myself:
        res = ""
        res += struct.pack('I',len(func_data))
        res += func_data
        res += struct.pack('I',num_similars)

        # Add message type:
        res = dword_pack(MsgTypes.REQUEST_SIMILARS,res)

        # Compare the two results:
        self.assertEqual(data,res)


    def test_parse_msg_response_similars(self):
        """
        Make sure that parse_msg_response_similars manages to parse a message I
        create.
        """
        # Two results:
        name1 = 'name1'
        comment1 = 'comment1'
        sim_grade1 = 7

        name2 = 'name1'
        comment2 = 'comment1'
        sim_grade2 = 7

        msg = ""
        # Two records:
        msg += struct.pack('I',2)

        # First record:
        msg += struct.pack('I',len(name1))
        msg += name1
        msg += struct.pack('I',len(comment1))
        msg += comment1
        msg += struct.pack('I',sim_grade1)

        # Second record:
        msg += struct.pack('I',len(name2))
        msg += name2
        msg += struct.pack('I',len(comment2))
        msg += comment2
        msg += struct.pack('I',sim_grade2)

        similars = parse_msg_response_similars(msg)

        self.assertEqual(len(similars),2)
        self.assertEqual(similars[0].name,name1)
        self.assertEqual(similars[0].comment,comment1)
        self.assertEqual(similars[0].sim_grade,sim_grade1)

        self.assertEqual(similars[1].name,name2)
        self.assertEqual(similars[1].comment,comment2)
        self.assertEqual(similars[1].sim_grade,sim_grade2)


###################################################################


LOCAL_PORT = 54321

class TestTCPFrameClient(unittest.TestCase):
    def test_basic_send_recv(self):
        """
        Test basic send/recv methods between TCPFrameClient and a sample server
        socket.
        """

        # Create a listening server socket:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('',LOCAL_PORT))
        s.listen(5)

        # Connect FrameClient to server:
        tfc = TCPFrameClient(('127.0.0.1',LOCAL_PORT))

        # Accept connection on the server side:
        sock,addr = s.accept()

        # Send a frame from the TCPFrameClient to the server socket:
        frame = 'hello'
        tfc.send_frame(frame)
        # Read 4 bytes first:
        length = sock.recv(4)
        length_int = struct.unpack('I',length)[0]
        self.assertEquals(length_int,len(frame))
        # Receive the rest of the frame:
        r_frame = sock.recv(length_int)

        self.assertEquals(r_frame,frame)

        # Send a frame from the server socket to the TCPFrameClient:
        frame = 'How are you doing?'
        data = len_prefix_pack(frame)
        sock.send(data)
        r_frame = tfc.recv_frame()
        self.assertEquals(r_frame,frame)

        # Close server socket:
        sock.close()

        # We expect to get a None frame on the TCPFrameClient side:
        frame = tfc.recv_frame()
        self.assertEquals(frame,None)

        # Close listening socket:
        s.close()

        # Close TCPFrameClient:
        tfc.close()

