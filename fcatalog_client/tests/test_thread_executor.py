
import unittest
import time

from fcatalog_client.thread_executor import \
        ThreadExecutor,ThreadExecutorError


class TestThreadExecutor(unittest.TestCase):
    def test_basic_running(self):
        """
        Test basic operation of ThreadExecutor by running simple functions
        serially.
        """
        te = ThreadExecutor()
        # Run a basic function:
        t = te.execute(lambda :True)

        # Wait for thread to finish:
        t.join()

        # Run another basic function (This time with an argument):
        t = te.execute(lambda x:x+1,5)

        # Wait for thread to finish:
        t.join()

    def test_already_running(self):
        """
        Make sure that ThreadExecutor doesn't let two threads run at the same
        time.
        """
        te = ThreadExecutor()

        def my_func():
            time.sleep(0.01)

        # Try to run two threds at the same time:
        t1 = te.execute(my_func)

        # The second attempt to run the function should raise an exception,
        # because the first one is already running:
        with self.assertRaises(ThreadExecutorError):
            t2 = te.execute(my_func)

        # Wait for the first thread to finish:
        t1.join()

        # After the first thread has finished, we can run another one:
        t3 = te.execute(lambda :True)

        # Wait for t3 to finish execution:
        t3.join()


