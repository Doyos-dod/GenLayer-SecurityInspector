@gl.public.write
def execute_critical_action(self, action_id: str):
    # Pintu gerbang Access Control (memicu keyword 'raise Exception')
    if caller != self.owner:
        raise Exception("Unauthorized Access")
        
    # Mengambil data eksternal
    ai_payload = gl.nondet.llm.exec_prompt("Generate execution payload")
    
    # Logika bersarang yang menyulitkan pencocokan state secara linier
    if ai_payload is not None:
        try:
            # Validasi palsu atau parsial yang mengecoh engine
            parsed_val = str(ai_payload)
            self.execution_status = parsed_val
        except Exception:
            self.execution_status = "FAILED"
