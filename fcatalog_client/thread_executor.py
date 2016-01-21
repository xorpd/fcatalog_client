import threading

class ThreadExecutorError(Exception): pass

# Thread executor. Can run only one thread at a time.
class ThreadExecutor(object):
    def __init__(self):
        # Currently not running:
        self._is_running = False

    def execute(self,func,*args,**kwargs):
        """
        Execute function in a new thread.
        Returns a handle to the created thread.
        """
        if self._is_running:
            raise ThreadExecutorError('Already running!')

        self._is_running = True

        def worker():
            # Run the function:
            try:
                func(*args,**kwargs)
            finally:
                # Mark finished running when the execution
                # of the function is done.
                self._is_running = False

        # Run the worker in a new thread:
        t = threading.Thread(target=worker)
        t.start()

        return t


