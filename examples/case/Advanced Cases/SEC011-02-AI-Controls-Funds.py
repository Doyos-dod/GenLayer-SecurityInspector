# { "Depends": "py-genlayer:test" }

from genlayer import *

class AITreasury(gl.Contract):

    balance: u256

    def __init__(self):
        self.balance = 1000

    @gl.public.write
    def review(self):

        decision = gl.nondet.llm.exec_prompt(
            "Approve withdrawal?"
        )

        if decision == "YES":

            self.balance = 0
