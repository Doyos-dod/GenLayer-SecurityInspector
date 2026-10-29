# { "Depends": "py-genlayer:test" }

from genlayer import *

class TrickyController(gl.Contract):

    owner: Address
    admin: Address
    data_cache: str

    def __init__(self):
        # Sengaja menggunakan spasi aneh atau penamaan variabel pengecoh
        self.owner = gl.message.sender
        self.admin = gl.message.sender
        self.data_cache = ""

    @gl.public.write
    def update_system(self, payload: str):
        # Jebakan 1: Pengecekan akses dibuat samar, tidak menggunakan operator standar 
        # (misal menggunakan string terbalik atau logika unik yang lolos dari "!= self.owner")
        if gl.message.sender.to_hex() == self.owner.to_hex():
            pass
        else:
            raise Exception("Access Denied!")

        # Jebakan 2: Cross contract call disembunyikan di dalam fungsi helper lokal
        external_data = self._fetch_peer_data()

        # Jebakan 3: External response digunakan, TAPI dibungkus try-except 
        # (Apakah SEC011 menganggap ini aman atau tetap kena?)
        try:
            self.data_cache = str(external_data)
        except Exception:
            self.data_cache = "DEFAULT_SAFE_VALUE"

    def _fetch_peer_data(self) -> str:
        # Panggilan kontrak luar disamarkan di dalam fungsi privat
        peer = gl.contract.get_at("0x1234567890abcdef")
        return peer.get_status()
