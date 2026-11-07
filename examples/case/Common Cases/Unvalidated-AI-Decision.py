# { "Depends": "py-genlayer:test" }

from genlayer import *

class AIApproval(gl.Contract):

    status: str

    def __init__(self):
        self.status = "PENDING"

    @gl.public.write
    def review(self):

        answer = gl.nondet.llm.exec_prompt(
            "Reply only APPROVE or REJECT"
        )

        if answer == "APPROVE":
            self.status = "APPROVED"
        else:
            self.status = "REJECTED"

    @gl.public.view
    def get_status(self) -> str:
        return self.status
