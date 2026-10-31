# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# 1. PELANGGARAN LINTING 1: Impor terlarang (os, sys, random)
import os
import sys
import random

from genlayer import *

class ChaosContractLintFail(gl.Contract):
    score: u256
    findings_count: u256
    risk_level: str
    findings: str
    
    status: str
    trail: str
    price: u256
    
    # 2. PELANGGARAN LINTING 2: Menggunakan struktur data mentah (dict/list) di state
    active_cache: dict
    user_list: list

    def __init__(self):
        self.score = u256(100)
        self.findings_count = u256(0)
        self.risk_level = "LOW"
        self.findings = ""
        
        self.status = "INIT"
        self.trail = ""
        self.price = u256(0)
        
        # Inisialisasi struktur data terlarang di state
        self.active_cache = {}
        self.user_list = []

    @gl.public.write
    def trigger_violations(self, input_prompt: str):
        # Menggunakan random (yang dilarang GenVM) untuk logika nondeterministic ilegal
        lucky_number = random.randint(1, 100)
        
        if lucky_number > 50:
            self.status = "WIN"
        else:
            self.status = "LOSE"

        # Membawa sisa struktur ChaosContract v2 (LLM & Web)
        web_raw = gl.nondet.web.get("https://api.chaos.test/data")
        ai_resp = gl.nondet.llm.exec_prompt(input_prompt)
        
        self.price = web_raw
