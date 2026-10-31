# { "Depends": "py-genlayer:test" }

from genlayer import *

class CrossContract:

    @gl.public.write
    def execute(self):

        target = gl.contract.get_at(
            "0x123456"
        )

        return target
