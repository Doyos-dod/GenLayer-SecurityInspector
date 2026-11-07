# { "Depends": "py-genlayer:test" }

from genlayer import *

class PriceFeed(gl.Contract):

    price: str

    @gl.public.write
    def update(self):

        self.price = gl.nondet.web.get(
            "https://example.com/price"
        )
