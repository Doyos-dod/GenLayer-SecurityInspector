# { "Depends": "py-genlayer:chaos-pkg-v1" }

from genlayer import *

class ChaosContractV2(gl.Contract):
    score: u256
    findings_count: u256
    risk_level: str
    findings: str
    
    status: str
    trail: str
    price: u256
    data_cache: str
    execution_status: str

    def __init__(self):
        self.score = u256(100)
        self.findings_count = u256(0)
        self.risk_level = "LOW"
        self.findings = ""
        
        self.status = "INIT"
        self.trail = ""
        self.price = u256(0)
        self.data_cache = ""
        self.execution_status = "IDLE"

    @gl.public.write
    def stress_test_all_rules(self, input_prompt: str):
        # 1. SEC007 & SEC015 Bypass Vector (Access Control Exception trap)
        # Memiliki raise Exception di awal untuk mengecoh parser global SEC011
        if self.status == "LOCKED":
            raise Exception("Contract is locked")

        # 2. SEC003: Nondeterministic Execution Trigger
        gl.vm.run_nondet_default()

        # 3. SEC004: Timestamp Dependency
        current_time = now()

        # 4. SEC005: Transaction Time Dependency
        tx_time = created()

        # 5. SEC006: Unbounded Storage Growth Trigger
        self.trail += f" | Executed at {current_time} - {tx_time}"

        # 6. SEC002: Cross Contract Call
        peer_data = gl.contract.get_at("0x1234567890abcdef").fetch_status()

        # 7. SEC008: External Web Access (GET & RENDER)
        web_raw = gl.nondet.web.get("https://api.chaos.test/data)
        web_view = gl.nondet.web.render("https://api.chaos.test/ui)

        # 8. SEC009 & SEC010: Excessive LLM Usage (Memanggil LLM >= 5 kali untuk memicu Medium Risk Excessive AI)
        ai_1 = gl.nondet.llm.exec_prompt(input_prompt)
        ai_2 = exec_prompt("Analyze step 1")
        ai_3 = llm_call("Analyze step 2")
        ai_4 = gl.nondet.llm.exec_prompt("Summarize risk")
        ai_5 = exec_prompt("Final check")

        # 9. SEC011: Unvalidated External Response + Try-Except Bypass
        # Mengonsumsi data dari LLM/Web/Cross-Contract dan memasukkannya ke state 
        # tanpa validasi murni, terlindung di dalam blok try-except lokal.
        try:
            parsed_payload = str(ai_1)
            self.execution_status = parsed_payload
        except Exception:
            self.execution_status = "SAFE_FALLBACK"

        # State update tambahan dari data web tanpa type casting / require
        self.price = web_raw
