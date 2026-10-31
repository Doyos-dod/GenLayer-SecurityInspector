# { "Depends": "py-genlayer:test" }

from genlayer import *

class TimeContract:

    @gl.public.write
    def execute(self):

        current = now()

        return current
