# A module that helps with writing thread safe ida code.
# Taken from: 
# http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging

import functools
import idaapi

import threading
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

# Get a thread context.
thread_local = threading.local()

# Enum for safety modes. Higher means safer:
class IDASafety:
    SAFE_NONE = 0
    SAFE_READ = 1
    SAFE_WRITE = 2


# A class for keeping the safety state with respect to current function
# call in the current thread.
class SafetyState:
    def __init__(self):
        # Current safety:
        self.cur_safety = IDASafety.SAFE_NONE

        # Call stack through safety wrappers.
        # Useful for debugging.
        self.call_stack = []


def sync_wrapper(ff,safety_mode):
    """
    Call a function ff with a specific IDA safety_mode.
    Handle cases of a safe function calling another safe function.
    It is possible for a highly safe function to call function of the same
    safety requirement or lower, but it is not possible for a function with a
    low safety requirement to call a function with a high safety requirement.
    """
    logger.debug('sync_wrapper: {}, {}'.format(ff.__name__,safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ,IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode,ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    # If safety_state is not present, set it to be SAFE_NONE:
    if not hasattr(thread_local,'safety_state'):
        thread_local.safety_state = SafetyState()

    # Check if we have some safety level set up:
    if thread_local.safety_state.cur_safety != IDASafety.SAFE_NONE:
        if safety_mode > thread_local.safety_state.cur_safety:
            error_str = ('Requested high safety mode {} inside low '
                    'safety mode {}. Call stack: {}').format(\
                    safety_mode,thread_local.safety_state.cur_safety,\
                    thread_local.safety_state.call_stack)
            logger.error(error_str)
            raise IDASyncError(error_str)
        # Otherwise, the current safety level is enough:
        return ff()

    # No safety level is set up:
    res_container = Queue.Queue()

    def runned():
        logger.debug('Inside runned')
        thread_local.safety_state.cur_safety = safety_mode
        thread_local.safety_state.call_stack.append(ff.__name__)
        try:
            res_container.put(ff())
        finally:
            thread_local.safety_state.cur_safety = IDASafety.SAFE_NONE
            thread_local.safety_state.call_stack.pop()
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
