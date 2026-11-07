# { "Depends": "py-genlayer:test" }

from genlayer import *

class WeatherLock(gl.Contract):

    status: str

    def __init__(self):
        self.status = "OPEN"

    @gl.public.write
    def update(self):

        weather = gl.nondet.web.get(
            "https://weather.example"
        )

        if weather == "STORM":

            self.status = "LOCKED"
