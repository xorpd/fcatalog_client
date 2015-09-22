
def blockify(iterator,block_size):
    """
    Given an iterator, return blocks of size block_size, except for the last
    block which might be shorter.
    """

    cur_block = []
    for x in iterator:
        cur_block.append(x)
        if len(cur_block) >= block_size:
            yield cur_block
            cur_block = []

    # Yield the last block:
    if len(cur_block) > 0:
        yield cur_block
