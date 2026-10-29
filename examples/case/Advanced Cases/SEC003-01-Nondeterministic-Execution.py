# { "Depends": "py-genlayer:test" }

from genlayer import *

class ValidatorVote(gl.Contract):

    result: str

    @gl.public.write
    def vote(self):

        self.result = gl.vm.run_nondet_default(
            "leader",
            "validator"
        )
