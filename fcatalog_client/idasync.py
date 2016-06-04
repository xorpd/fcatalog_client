# A module that helps with writing thread safe ida code.
# Taken from: 
# http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging

import functools
import idaapi

import Queue

class IDASyncError(Exception): pass

# Important note: Always make sure the return value from your function f is a
# copy of the data you have gotten from IDA, and not the original data.
#
# Example:
# --------
#
# Do this:
#
#   @idaread
#   def ts_Functions():
#       return list(idautils.Functions())
#
# Don't do this:
#
#   @idaread
#   def ts_Functions():
#       return idautils.Functions()
#

logger = logging.getLogger(__name__)

# Enum for safety modes. Higher means safer:
class IDASafety:
    SAFE_NONE = 0
    SAFE_READ = 1
    SAFE_WRITE = 2


call_stack = Queue.LifoQueue()


def sync_wrapper(ff,safety_mode):
    """
    Call a function ff with a specific IDA safety_mode.
    """
    logger.debug('sync_wrapper: {}, {}'.format(ff.__name__,safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ,IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode,ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    # No safety level is set up:
    res_container = Queue.Queue()

    def runned():
        logger.debug('Inside runned')

        # Make sure that we are not already inside a sync_wrapper:
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                'function {} from {}').format(ff.__name__,last_func_name)
            logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        finally:
            call_stack.get()
            logger.debug('Finished runned')

    ret_val = idaapi.execute_sync(runned,safety_mode)
    res = res_container.get()
    return res


def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args,**kwargs):
        ff = functools.partial(f,*args,**kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff,idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args,**kwargs):
        ff = functools.partial(f,*args,**kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff,idaapi.MFF_READ)
    return wrapper
