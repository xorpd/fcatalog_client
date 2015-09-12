import idaapi
import idautils
import idc
from db_endpoint import DBEndpoint,TCPFrameClient

class FCatalogClientError(Exception): pass

# Minimum function size (in bytes) to be considered when trying to find
# similars.
MIN_FUNC_LENGTH = 0x40

FCATALOG_PREFIX = 'FCATALOG__'

def get_func_length(func_addr):
    """
    Return function's length.
    """
    # First check if this is a chunked function.
    # If so, we abort.
    if is_func_chunked(func_addr):
        raise FCatalogClientError('Function {:X} is chunked. Can not calculate'
                ' length.'.format(func_addr))


    # Get the end of the function:
    func_end = idc.GetFunctionAttr(func_addr,idc.FUNCATTR_END)

    if func_end < func_addr:
        raise FCatalogClientError('Function {:X} has end lower than start'.\
                format(func_addr))

    # Calculate length and return:
    return func_end - func_addr


def get_func_data(func_addr):
    """
    Get function's data
    """
    func_length = get_function_length(func_addr)
    func_data = idc.GetManyBytes(func_addr,func_length)
    if func_data is None:
        raise FCatalogClientError('Failed reading function {:X} data'.\
                format(func_addr))

def get_func_comment(func_addr):
    """
    Get Function's comment. Ignore fcatalog prefixes.
    """
    raise NotImplementedError()


#########################################################################

def is_fcatalog_func(func_addr):
    """
    Have we obtained the name for this function from fcatalog server?
    We know this by the name of the function.
    """
    return func_name.startswith(FCATALOG_PREFIX):

def is_func_named(func_addr):
    """
    Check if a function was ever named by the user.
    """
    func_name = idc.GetFunctionName(func_addr)

    # Avoid functions like sub_409f498:
    if func_name.startswith('sub_'):
        return False

    # Avoid MAYBE functions:
    if ('_maybe' in func_name.lower()) or \
            ('maybe_' in func_name.lower()):
        return False

    # Avoid reindexing FCATALOG functions:
    if is_fcatalog_func(func_addr):
        return False

    return True


def is_func_long_enough(func_addr):
    """
    Check if a given function is of suitable size to be commited.
    """
    func_length = get_func_length(func_addr)
    if func_length < MIN_FUNC_LENGTH:
        return False

    return True


def is_func_chunked(func_addr):
    """
    Check if a function is divided into chunks.
    """
    # Idea for this code is from:
    # http://code.google.com/p/idapython/source/browse/trunk/python/idautils.py?r=344

    num_chunks = 0
    func_iter = idaapi.func_tail_iterator_t( idaapi.get_func( func_addr ) )
    status = func_iter.main()
    while status:
        chunk = func_iter.chunk()
        num_chunks += 1
        # yield (chunk.startEA, chunk.endEA)
        status = func_iter.next()

    return (num_chunks > 1)


def is_func_commit_candidate(func_addr):
    """
    Is this function a candidate for committing?
    """
    # Don't commit if chunked:
    if is_func_chunked(func_addr):
        return False

    if not is_func_named(func_addr):
        return False

    if not is_func_long_enough(func_addr):
        return False

    return True


class FCatalogClient(object):
    def __init__(self,remote,db_name):
        # Keep remote address:
        self._remote = remote

        # Keep remote db name:
        self._db_name = db_name

    def commit_funcs(self):
        """
        Commit all the named functions from this idb to the server.
        """
        # Set up a connection to remote db:
        frame_endpoint = TCPFrameClient(self._remote)
        fdb = DBEndpoint(frame_endpoint,self._db_name)

        for func_addr in idautils.Functions():
            if not is_func_commit_candidate(func_addr):
                continue

            func_name = idc.GetFunctionName(func_addr)
            func_comment = get_func_comment(func_addr)
            func_data = get_func_data(func_addr)

            fdb.add_function(func_name,func_comment,func_data)

        fdb.close()


    def find_similars(self):
        """
        For each unnamed function in this database find a similar functions
        from the fcatalog remote db, and rename appropriately.
        """
        pass


    def clean_idb(self):
        """
        Clean all fcatalog marks and names from this idb.
        """
        pass




