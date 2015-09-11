import unittest
import struct

from fcatalog_client.db_endpoint import \
    len_prefix_pack,len_prefix_unpack,dword_pack,dword_unpack,\
    build_msg_choose_db,build_msg_add_function,build_msg_get_similars,\
    parse_msg_reponse_similars


class TestPacking(unittest.TestCase):
    def test_len_prefix_pack(self):
        """
        Test len_prefix_{pack,unpack} functions.
        """
        # Simple packing and unpacking:
        msg = 'Example msg'
        data = len_prefix_pack(msg)
        assert len(data) == len(msg) + 4
        msg1,data1 = len_prefix_unpack(data)

        assert msg1 == msg
        assert len(data1) == 0

        # Dealing with extra data:
        extra_data = 'some extra'
        longer_data = data + extra_data
        msg2,data2 = len_prefix_unpack(data)
        assert msg2 == msg
        assert data2 == extra_data

    def test_dword_pack(self):
        """
        Test dword_{pack,unpack} functions.
        """
        msg = 'This is example msg'
        num = 0x1337
        data = dword_pack(num,msg)
        assert len(data) == len(msg) + 4
        num1,msg1 = dword_unpack(data)

        assert num1 == num
        assert msg1 == msg


class TestBuildMessages(unittest.TestCase):
    def test_build_msg_choose_db(self):
        db_name = 'my_db_name'
        data = build_msg_choose_db(db_name)
        assert struct.unpack('I',data[0:4])[0] == len(db_name)
        assert data[4:] == db_name

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

        # Compare the two results:
        assert data == res

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

        # Compare the two results:
        assert data == res


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

        assert len(similars) == 2
        assert similars[0].name == name1
        assert similars[0].comment == comment1
        assert similars[0].sim_grade == sim_grade1

        assert similars[1].name == name2
        assert similars[1].comment == comment2
        assert similars[1].sim_grade == sim_grade2

