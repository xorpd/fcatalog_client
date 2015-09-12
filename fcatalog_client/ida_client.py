import idaapi
import idautils
import idc
from db_endpoint import DBEndpoint,TCPFrameClient

class FCatalogClientError(Exception): pass

# Minimum function size (in bytes) to be considered when trying to find
# similars.
MIN_FUNC_LENGTH = 0x40

FCATALOG_FUNC_NAME_PREFIX = 'FCATALOG__'
FCATALOG_COMMENT_PREFIX = '%%%'

SIMILARITY_CUT = 5

NUM_SIMILARS = 1

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
    func_length = get_func_length(func_addr)
    func_data = idc.GetManyBytes(func_addr,func_length)
    if func_data is None:
        raise FCatalogClientError('Failed reading function {:X} data'.\
                format(func_addr))

    return func_data


def get_func_comment(func_addr):
    """
    Get Function's comment.
    """
    # Currently not implemented:
    return ""

def set_func_comment(func_addr,comment):
    """
    Set function's comment.
    """
    # Currently not implemented:
    pass


#########################################################################

def is_func_fcatalog(func_addr):
    """
    Have we obtained the name for this function from fcatalog server?
    We know this by the name of the function.
    """
    func_name = idc.GetFunctionName(func_addr)
    return func_name.startswith(FCATALOG_FUNC_NAME_PREFIX)

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

    # Avoid RELATED functions:
    if ('_related' in func_name.lower()) or \
            ('related_' in func_name.lower()):
        return False

    # Avoid reindexing FCATALOG functions:
    if is_func_fcatalog(func_addr):
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
    func_iter = idaapi.func_tail_iterator_t(idaapi.get_func(func_addr))
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

def is_func_find_candidate(func_addr):
    """
    Is this function a candidate for finding from database (Finding similars
    for this function?)
    """
    if is_func_chunked(func_addr):
        return False

    if is_func_named(func_addr):
        return False

    if not is_func_long_enough(func_addr):
        return False

    return True



###########################################################################

def strip_comment_fcatalog(comment):
    """
    Remove all fcatalog comments from a given comment.
    """
    res_lines = []

    # Get only lines that don't start with FCATALOG_COMMENT_PREFIX:
    lines = comment.splitlines()
    for ln in lines:
        if ln.startswith(FCATALOG_COMMENT_PREFIX):
            continue
        res_lines.append(ln)

    return '\n'.join(res_lines)

def add_comment_fcatalog(comment,fcatalog_comment):
    """
    Add fcatalog comment to a function.
    """
    res_lines = []

    # Add the fcatalog_comment lines with a prefix:
    for ln in fcatalog_comment.splitlines():
        res_lines.append(FCATALOG_COMMENT_PREFIX + ' ' + ln)

    # Add the rest of the comment lines:
    for ln in comment.splitlines():
        res_lines.append(ln)

    return '\n'.join(res_lines)

def make_fcatalog_name(func_name,sim_grade):
    """
    Make an fcatalog function name using function name and sim_grade.
    """
    lres = []
    lres.append(FCATALOG_FUNC_NAME_PREFIX)
    lres.append('{:0>2}__'.format(sim_grade))
    lres.append(func_name)
    return ''.join(lres)


###########################################################################


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
            func_comment = strip_comment_fcatalog(get_func_comment(func_addr))
            func_data = get_func_data(func_addr)

            fdb.add_function(func_name,func_comment,func_data)

        # Close db:
        fdb.close()


    def find_similars(self):
        """
        For each unnamed function in this database find a similar functions
        from the fcatalog remote db, and rename appropriately.
        """
        # Set up a connection to remote db:
        frame_endpoint = TCPFrameClient(self._remote)
        fdb = DBEndpoint(frame_endpoint,self._db_name)

        for func_addr in idautils.Functions():
            if not is_func_find_candidate(func_addr):
                continue

            func_data = get_func_data(func_addr)
            similars = fdb.request_similars(func_data,NUM_SIMILARS)

            if len(similars) == 0:
                # No similars found.
                continue

            # Get the first entry (Highest similarity):
            fsim = similars[0]

            # Discard if doesn't pass the similarity cut:
            if fsim.sim_grade < SIMILARITY_CUT:
                continue

            # Set new name:
            new_name = make_fcatalog_name(fsim.name,fsim.sim_grade)
            idc.MakeName(func_addr,new_name)

            # Add the comments from the fcatalog entry:
            func_comment = get_func_comment(func_addr)
            func_comment_new = \
                    add_comment_fcatalog(func_comment,fsim.comment)
            set_func_comment(func_addr,func_comment_new)


        # Close db:
        fdb.close()


    def clean_idb(self):
        """
        Clean all fcatalog marks and names from this idb.
        """
        for func_addr in idautils.Functions():
            # Skip functions that are not fcatalog named:
            if not is_func_fcatalog(func_addr):
                continue

            # Clear function's name:
            idc.MakeName(func_addr,'')

            # Clean fcatalog comments from the function:
            func_comment = get_func_comment(func_addr)
            set_func_comment(func_addr,strip_comment_fcatalog(func_comment))

