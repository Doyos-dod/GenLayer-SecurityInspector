# { "Depends": "py-genlayer:test" }

from genlayer import *

class TimedSale(gl.Contract):

    closed: bool

    def __init__(self):
        self.closed = False

    @gl.public.write
    def check(self):

        if now() > 100000:

            self.closed = True
