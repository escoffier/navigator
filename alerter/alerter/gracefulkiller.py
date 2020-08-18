# -*- coding: utf-8 -*-
"""A Graceful Killer
"""
import queue
import signal


class GracefulKillerDone(Exception):
    """An exception to signal this graceful killer is done
    """


class GracefulKiller:
    """GracefullKiller handles the signal capturing and exit the program gracefully.
    """

    def __init__(self, num_of_threads=1):
        """GracefulKiller constructor

        Arguments:
            num_of_threads {integer} -- number of threads this killer needs to stop
        """
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        self.num_of_threads = num_of_threads
        self.stop_q = queue.Queue(maxsize=num_of_threads)

    def exit_gracefully(self, signum, frame):
        """This function runs after the signals are captured

        Arguments:
            signum -- signal number
            frame -- current stack frame
        """
        print("signal captured: {} {}".format(signum, frame))
        for _ in range(self.num_of_threads):
            self.stop_q.put(None)

    def sleep(self, secs=None):
        """sleep can get short circuited when getting a message in the stop_q

        Arguments:
            secs {integer} -- number of seconds the killer is sleeping
        """
        try:
            self.stop_q.get(timeout=secs)
            raise GracefulKillerDone()
        except queue.Empty:
            return
