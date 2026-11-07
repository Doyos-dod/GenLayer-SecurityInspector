# { "Depends": "py-genlayer:test" }

from genlayer import *

class Vault(gl.Contract):

    balance: u256

    def __init__(self):
        self.balance = 1000

    @gl.public.write
    def withdraw_all(self):
        self.balance = 0
