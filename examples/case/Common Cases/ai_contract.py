# { "Depends": "py-genlayer:test" }

from genlayer import *

class AIContract:

    @gl.public.write
    def ask(self):

        answer = gl.nondet.llm.exec_prompt(
            "What is blockchain?"
        )

        return answer
