@gl.public.write
def fetch_external_price(self):
    # Mengambil data dari web tanpa sanitasi langsung disimpan ke state
    raw_data = gl.nondet.web.get("https://api.example.com/price)
    self.price = raw_data
