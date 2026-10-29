# { "Depends": "py-genlayer:test" }

from genlayer import *

class AIAnalyzer(gl.Contract):

    @gl.public.write
    def analyze(self):

        a = gl.nondet.llm.exec_prompt(
            "Risk?"
        )

        b = gl.nondet.llm.exec_prompt(
            "Score?"
        )

        return a + b
