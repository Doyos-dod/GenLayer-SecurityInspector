# { "Depends": "py-genlayer:test" }

from genlayer import *

class AIHelper(gl.Contract):

    @gl.public.write
    def ask(self):

        answer = gl.nondet.llm.exec_prompt(
            "What is blockchain?"
        )

        return answer
