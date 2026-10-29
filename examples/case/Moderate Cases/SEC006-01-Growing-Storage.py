# { "Depends": "py-genlayer:test" }

from genlayer import *

class Logger(gl.Contract):

    trail: str

    def __init__(self):
        self.trail = ""

    @gl.public.write
    def log(self, message: str):

        self.trail += message
