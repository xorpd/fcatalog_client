from __future__ import print_function
import logging
import re

from db_endpoint import DBEndpoint,TCPFrameClient
from utils import blockify
from thread_executor import ThreadExecutor, ThreadExecutorError
from ida_ts import get_func_length, get_func_data, get_func_comment, \
        Functions, first_func_addr, GetFunctionName, is_func_chunked, make_name

class FCatalogClientError(Exception): pass

logger = logging.getLogger(__name__)

# Minimum function size (in bytes) to be considered when trying to find
# similars.
MIN_FUNC_LENGTH = 0x60

FCATALOG_FUNC_NAME_PREFIX = 'FCATALOG__'
FCATALOG_COMMENT_PREFIX = '%%%'

# The grade of similarity for each function is a number between 0 and this
# constant (Inclusive):
MAX_SIM_GRADE = 16

# Amount of similar functions to return in every inquiry for similars function
# for a specific function:
NUM_SIMILARS = 1

# Amount of functions to be sent together to remote server when looking for
# similars:
GET_SIMILARS_BATCH_SIZE = 20


#########################################################################

def is_func_fcatalog(func_addr):
    """
    Have we obtained the name for this function from fcatalog server?
    We know this by the name of the function.
    """
    logger.debug('is_func_fcatalog {}'.format(func_addr))
    func_name = GetFunctionName(func_addr)
    return func_name.startswith(FCATALOG_FUNC_NAME_PREFIX)


def is_func_long_enough(func_addr):
    """
    Check if a given function is of suitable size to be commited.
    """
    logger.debug('is_func_long_enough {}'.format(func_addr))
    func_length = get_func_length(func_addr)
    if func_length < MIN_FUNC_LENGTH:
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

def make_fcatalog_name(func_name,sim_grade,func_addr):
    """
    Make an fcatalog function name using function name and sim_grade.
    """
    lres = []
    lres.append(FCATALOG_FUNC_NAME_PREFIX)
    lres.append('{:0>2}__'.format(sim_grade))
    lres.append(func_name)
    lres.append('__{:0>8X}'.format(func_addr & 0xffffffff))
    return ''.join(lres)


###########################################################################



class FCatalogClient(object):
    def __init__(self,remote,db_name,exclude_pattern=None):
        # Keep remote address:
        self._remote = remote

        # Keep remote db name:
        self._db_name = db_name

        # A thread executor. Allows only one task to be run every time.
        self._te = ThreadExecutor()

        # A regexp pattern that identifies functions that are not named, and
        # should be ignored.
        self._exclude_pattern = exclude_pattern

        
        # A thread safe print function. I am not sure if this is rquired. It is
        # done to be one the safe side:
        self._print = print

    def _is_func_named(self,func_addr):
        """
        Check if a function was ever named by the user.
        """
        logger.debug('_is_func_named {}'.format(func_addr))
        func_name = GetFunctionName(func_addr)

        # Avoid functions like sub_409f498:
        if func_name.startswith('sub_'):
            return False

        # If exclude_pattern was provided, make sure that the function
        # name does not match it:
        if self._exclude_pattern is not None:
            mt = re.match(self._exclude_pattern,func_name)
            if mt is not None:
                return False

        # Avoid reindexing FCATALOG functions:
        if is_func_fcatalog(func_addr):
            return False

        return True

    def _is_func_commit_candidate(self,func_addr):
        """
        Is this function a candidate for committing?
        """
        # Don't commit if chunked:
        if is_func_chunked(func_addr):
            return False

        if not self._is_func_named(func_addr):
            return False

        if not is_func_long_enough(func_addr):
            return False

        return True

    def _is_func_find_candidate(self,func_addr):
        """
        Is this function a candidate for finding from database (Finding similars
        for this function?)
        """
        if is_func_chunked(func_addr):
            return False

        if self._is_func_named(func_addr):
            return False

        if not is_func_long_enough(func_addr):
            return False

        return True


    def _iter_func_find_candidates(self):
        """
        Iterate over all functions that are candidates for finding similars from
        the remote database.
        This function is IDA read thread safe.
        """
        for func_addr in Functions():
            if self._is_func_find_candidate(func_addr):
                yield func_addr


    def _commit_funcs_thread(self):
        """
        Commit all the named functions from this idb to the server.
        This is an IDA read thread safe function.
        """
        self._print('Commiting functions...')
        # Set up a connection to remote db:
        frame_endpoint = TCPFrameClient(self._remote)
        fdb = DBEndpoint(frame_endpoint,self._db_name)


        for func_addr in Functions():
            logger.debug('Iterating over func_addr: {}'.format(func_addr))
            if not self._is_func_commit_candidate(func_addr):
                continue

            func_name = GetFunctionName(func_addr)
            func_comment = strip_comment_fcatalog(get_func_comment(func_addr))
            func_data = get_func_data(func_addr)

            # If we had problems reading the function data, we skip it.
            if func_data is None:
                self._print('!> Skipping {}'.format(func_name))
                continue

            fdb.add_function(func_name,func_comment,func_data)
            self._print(func_name)

        # Close db:
        fdb.close()
        self._print('Done commiting functions.')

    def commit_funcs(self):
        """
        Commit all functions from this IDB to the server.
        """
        try:
            t = self._te.execute(self._commit_funcs_thread)
        except ThreadExecutorError:
            print('Another operation is currently running. Please wait.')


    def _batch_similars(self,fdb,l_func_addr):
        """
        Given a list of function addresses, request similars for each of those
        functions. Then wait for all the responses, and return a list of tuples
        of the form: (func_addr,similars)
        This function is IDA read thread safe.
        """
        # Send requests for similars for every function in l_func_addr list:
        for func_addr in l_func_addr:
            func_data = get_func_data(func_addr)
            fdb.request_similars(func_data,1)

        # Collect responses from remote server:
        lres = []
        for func_addr in l_func_addr:
            similars = fdb.response_similars()
            lres.append((func_addr,similars))

        return lres


    def _find_similars_thread(self,similarity_cut,batch_size):
        """
        For each unnamed function in this database find a similar functions
        from the fcatalog remote db, and rename appropriately.
        This thread is IDA write thread safe.
        """
        self._print('Finding similars...')

        # Set up a connection to remote db:
        frame_endpoint = TCPFrameClient(self._remote)
        fdb = DBEndpoint(frame_endpoint,self._db_name)

        # Iterate over blocks of candidate functions addresses:
        for l_func_addr in blockify(self._iter_func_find_candidates(),\
                batch_size):
            # Send block to remote server and get results:
            bsimilars = self._batch_similars(fdb,l_func_addr)
            # Iterate over functions and results:
            for func_addr,similars in bsimilars:

                if len(similars) == 0:
                    # No similars found.
                    continue

                # Get the first entry (Highest similarity):
                fsim = similars[0]

                # Discard if doesn't pass the similarity cut:
                if fsim.sim_grade < similarity_cut:
                    continue

                old_name = GetFunctionName(func_addr)

                # Generate new name:
                new_name = make_fcatalog_name(fsim.name,fsim.sim_grade,func_addr)

                # If name matches old name, skip:
                if new_name == old_name:
                    continue

                # Set function to have the new name:
                make_name(func_addr,new_name)

                # Add the comments from the fcatalog entry:
                func_comment = get_func_comment(func_addr)
                func_comment_new = \
                        add_comment_fcatalog(func_comment,fsim.comment)
                set_func_comment(func_addr,func_comment_new)

                self._print('{} --> {}'.format(old_name,new_name))

        # Close db:
        fdb.close()

        self._print('Done finding similars.')

    def find_similars(self,similarity_cut,batch_size=GET_SIMILARS_BATCH_SIZE):
        """
        For each unnamed function in this database find a similar functions
        from the fcatalog remote db, and rename appropriately.
        """
        try:
            t = self._te.execute(self._find_similars_thread,\
                    similarity_cut,batch_size)
        except ThreadExecutorError:
            print('Another operation is currently running. Please wait.')


def clean_idb():
    """
    Clean all fcatalog marks and names from this idb.
    """
    print('Cleaning idb...')
    for func_addr in Functions():
        # Skip functions that are not fcatalog named:
        if not is_func_fcatalog(func_addr):
            continue

        print('{}'.format(GetFunctionName(func_addr)))
        # Clear function's name:
        make_name(func_addr,'')

        # Clean fcatalog comments from the function:
        func_comment = get_func_comment(func_addr)
        set_func_comment(func_addr,strip_comment_fcatalog(func_comment))
    print('Done cleaning idb.')

