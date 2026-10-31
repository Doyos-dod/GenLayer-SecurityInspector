# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *

class ChaosContract(gl.Contract):
    score: u256
    trail: str
    owner: str

    def __init__(self):
        self.score = u256(100)
        self.trail = ""
        self.owner = "0x123456789abcdef"

    @gl.public.write
    def dangerous_universal_function(self, user_payload: str):
        # -------------------------------------------------------------
        # SEC002: Cross Contract Call
        # -------------------------------------------------------------
        target_contract = gl.contract.get_at("0xTargetContractAddressHere")
        
        # -------------------------------------------------------------
        # SEC003: Nondeterministic Execution
        # -------------------------------------------------------------
        gl.vm.run_nondet_default()

        # -------------------------------------------------------------
        # SEC004 & SEC005: Timestamp & Transaction Time Dependency
        # -------------------------------------------------------------
        current_time = now()
        tx_creation = created()

        # -------------------------------------------------------------
        # SEC006: Unbounded Storage Growth
        # -------------------------------------------------------------
        self.trail += user_payload

        # -------------------------------------------------------------
        # SEC008: External Web Access (GET & RENDER)
        # -------------------------------------------------------------
        raw_web_data = gl.nondet.web.get("https://api.example.com/price")
        gl.nondet.web.render("https://example.com/dashboard")

        # -------------------------------------------------------------
        # SEC009 & SEC010: Excessive LLM Dependence (>= 5 Calls)
        # -------------------------------------------------------------
        ai_res_1 = gl.nondet.llm("Analyze threat 1")
        ai_res_2 = gl.nondet.llm("Analyze threat 2")
        ai_res_3 = exec_prompt("Analyze threat 3")
        ai_res_4 = exec_prompt("Analyze threat 4")
        ai_res_5 = llm_call("Analyze threat 5")

        # -------------------------------------------------------------
        # SEC011: Unvalidated External Response
        # raw_web_data digunakan langsung dalam 'if' tanpa require/assert/int()/json.loads
        # -------------------------------------------------------------
        if raw_web_data == "critical_alert":
            self.score = u256(0)

        # -------------------------------------------------------------
        # Catatan: Fungsi ini TIDAK MEMILIKI validasi owner/admin di dalam scope-nya,
        # sehingga ini akan memicu SEC007 (Missing Access Control - High Risk).
        # -------------------------------------------------------------
