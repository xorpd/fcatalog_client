import logging
import idautils
import idaapi
import idc
from idasync import idaread, idawrite

logger = logging.getLogger(__name__)

"""
This module exports thread safe ida functions.
The functions that begin with underscore ('_') are not thread safe.
"""

def _get_func_length(func_addr):
    """
    Return function's length.
    """
    logger.debug('_get_func_length: {}'.format(func_addr))
    # First check if this is a chunked function.
    # If so, we abort.
    if _is_func_chunked(func_addr):
        return None
        # raise FCatalogClientError('Function {:X} is chunked. Can not calculate'
        #        ' length.'.format(func_addr))

    # Get the end of the function:
    func_end = idc.GetFunctionAttr(func_addr,idc.FUNCATTR_END)

    if func_end < func_addr:
        return None
        # raise FCatalogClientError('Function {:X} has end lower than start'.\
        #        format(func_addr))

    # Calculate length and return:
    return func_end - func_addr

get_func_length = idaread(_get_func_length)

def _get_func_data(func_addr):
    """
    Get function's data
    """
    logger.debug('_get_func_data: {}'.format(func_addr))
    func_length = _get_func_length(func_addr)
    if func_length is None:
        return None
    func_data = idc.GetManyBytes(func_addr,func_length)
    if func_data is None:
        return None
        # raise FCatalogClientError('Failed reading function {:X} data'.\
        #        format(func_addr))

    return str(func_data)

get_func_data = idaread(_get_func_data)

def _get_func_comment(func_addr):
    """
    Get Function's comment.
    """
    # Currently not implemented:
    return ""

# An IDA read thread safe version:
get_func_comment = idaread(_get_func_comment)

def _set_func_comment(func_addr,comment):
    """
    Set function's comment.
    """
    # Currently not implemented:
    pass

# An IDA write thread safe version:
set_func_comment = idawrite(_set_func_comment)

def _Functions():
    """
    Thread safe IDA iteration over all functions.
    """
    logger.debug('_Functions')
    return list(idautils.Functions())

Functions = idaread(_Functions)

def _first_func_addr():
    """
    Get addr of the first function.
    IDA read thread safe.
    """
    logger.debug('_first_func_addr')
    if not start: start = idaapi.cvar.inf.minEA
    if not end:   end = idaapi.cvar.inf.maxEA

    # find first function head chunk in the range
    chunk = idaapi.get_fchunk(start)
    if not chunk:
        chunk = idaapi.get_next_fchunk(start)
    while chunk and chunk.startEA < end and (chunk.flags & idaapi.FUNC_TAIL) != 0:
        chunk = idaapi.get_next_fchunk(chunk.startEA)
    func = chunk
    return int(func.startEA)

first_func_addr = idaread(_first_func_addr)

def _GetFunctionName(func_addr):
    """
    Should be a thread safe version of GetFunctionName.
    """
    logger.debug('_GetFunctionName')
    return str(idc.GetFunctionName(func_addr))

GetFunctionName = idaread(_GetFunctionName)

def _is_func_chunked(func_addr):
    """
    Check if a function is divided into chunks.
    """
    logger.debug('is_func_chunked {}'.format(func_addr))
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

is_func_chunked = idaread(_is_func_chunked)

def _make_name(func_addr,func_name):
    """
    Set the name of function at address func_addr to func_name.
    This function is IDA write thread safe.
    """
    logger.debug('_make_name {}, {}'.format(func_addr,func_name))
    idc.MakeName(func_addr,func_name)
    idc.Refresh()

make_name = idawrite(_make_name)


