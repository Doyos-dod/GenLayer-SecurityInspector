# { "Depends": "py-genlayer:test" }

from genlayer import *

class Reader(gl.Contract):

    value: str

    @gl.public.write
    def read(self, address: Address):

        peer = gl.contract.get_at(address)

        self.value = peer.get_value()
