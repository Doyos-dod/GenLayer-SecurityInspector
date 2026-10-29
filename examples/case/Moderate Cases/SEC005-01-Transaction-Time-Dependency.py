# { "Depends": "py-genlayer:test" }

from genlayer import *

class TransactionGate(gl.Contract):

    status: str

    def __init__(self):
        self.status = "OPEN"

    @gl.public.write
    def check(self):

        if created() > 100000:

            self.status = "CLOSED"
