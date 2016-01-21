# A module that helps with writing thread safe ida code.
# Taken from: 
# http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/

import functools
import idaapi

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

def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        # We keep the result of the runned function using a result container:
        res_container = []
        def runned():
            res = ff()
            res_container.append(ff())

        ret_val = idaapi.execute_sync(runned, idaapi.MFF_WRITE)
        return res_container[0]
    return wrapper


def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        # We keep the result of the runned function using a result container:
        res_container = []
        def runned():
            res_container.append(ff())

        ret_val = idaapi.execute_sync(runned, idaapi.MFF_READ)
        return res_container[0]
    return wrapper
