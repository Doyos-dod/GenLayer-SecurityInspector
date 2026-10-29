# { "Depends": "py-genlayer:test" }

from genlayer import *

class Controller(gl.Contract):

    enabled: bool

    def __init__(self):
        self.enabled = False

    @gl.public.write
    def sync(self, address: Address):

        peer = gl.contract.get_at(address)

        status = peer.get_status()

        if status == "ACTIVE":

            self.enabled = True
