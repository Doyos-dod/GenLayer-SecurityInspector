# { "Depends": "py-genlayer:test" }

from genlayer import *

class WebContract:

    @gl.public.write
    def check(self):

        page = gl.nondet.web.get(
            "https://example.com"
        )

        return page
