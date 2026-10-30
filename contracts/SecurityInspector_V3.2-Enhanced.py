# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *

class SecurityInspector(gl.Contract):

    score: u256
    findings_count: u256
    risk_level: str
    findings: str

    high_count: u256
    medium_count: u256
    low_count: u256
    info_count: u256

    audit_version: str

    def __init__(self):
        self.score = u256(100)
        self.findings_count = u256(0)
        self.risk_level = "LOW"
        self.findings = ""

        self.high_count = u256(0)
        self.medium_count = u256(0)
        self.low_count = u256(0)
        self.info_count = u256(0)

        self.audit_version = "3.2-Enhanced"
        
    def _clean_comments(self, code: str) -> str:
        """Helper v3.2-Enhanced: Membuang komentar baris (#) untuk mencegah false positive"""
        lines = code.split("\n")
        cleaned_lines = []
        for line in lines:
            if "#" in line:
                line = line.split("#")[0]
            if line.strip():
                cleaned_lines.append(line)
        return "\n".join(cleaned_lines)

    @gl.public.write
    def analyze_source(self, source_code: str):

        score = 100
        findings = 0
        report = ""
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

        # Hasil pembersihan komentar untuk mendeteksi kode aktif
        clean_code = self._clean_comments(source_code)

        #
        # Analyzer Protection (Cek ukuran berdasarkan source_code mentah)
        #
        if len(source_code) > 50000:
            self.high_count = u256(1)
            self.score = u256(0)
            self.findings_count = u256(1)
            self.risk_level = "HIGH"

            self.findings = (
                "========================================\n"
                "GENLAYER SECURITY REPORT\n\n"
                "Security Score : 0\n"
                "Risk Level     : HIGH\n"
                "Total Findings : 1\n"
                "========================================\n\n"
                "========================================\n"
                "EXECUTIVE SUMMARY\n"
                "========================================\n\n"
                "High Risk Findings   : 1\n"
                "Medium Risk Findings : 0\n"
                "Low Risk Findings    : 0\n"
                "Info Findings        : 0\n\n"
                "Audit Engine Version : 3.2-Enhanced\n"
                "========================================\n\n"
                "HIGH RISK\n\n"
                "Issue:\n"
                "Source Code Too Large\n\n"
                "Explanation:\n"
                "The submitted source code exceeds the "
                "allowed size limit.\n\n"
                "Recommendation:\n"
                "Reduce source code size before analysis.\n"
            )
            return

        #
        # SEC001 Runtime Dependency (Cek metadata header dari source_code asli)
        #
        if "Depends" in source_code:
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "Runtime Dependency\n\n"
                "Explanation:\n"
                "The contract relies on a specific "
                "runtime dependency package.\n\n"
                "Impact:\n"
                "Runtime upgrades, compatibility changes, "
                "or dependency updates may affect contract "
                "behaviour and execution.\n\n"
                "Recommendation:\n"
                "Review dependency requirements and "
                "verify contract compatibility after "
                "runtime upgrades.\n"
                "========================================\n"
            )

        #
        # SEC002 Cross Contract Call (Menggunakan clean_code)
        #
        if (
            "gl.contract.get_at(" in clean_code or
            "gl.call(" in clean_code or
            "gl.send(" in clean_code
        ):
            score -= 5
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "Cross Contract Call\n\n"
                "Explanation:\n"
                "The contract interacts with another "
                "contract or external on-chain target.\n\n"
                "Impact:\n"
                "Execution results may depend on the "
                "behaviour and availability of external "
                "contracts.\n\n"
                "Recommendation:\n"
                "Validate external responses and handle "
                "unexpected failures safely.\n"
                "========================================\n"
            )

        #
        # SEC003 Nondeterministic Execution
        #
        if "gl.vm.run_nondet_default" in clean_code:
            score -= 5
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "Nondeterministic Execution\n\n"
                "Explanation:\n"
                "The contract uses nondeterministic "
                "execution mechanisms.\n\n"
                "Impact:\n"
                "Validators may receive different inputs "
                "or produce varying execution results.\n\n"
                "Recommendation:\n"
                "Validate nondeterministic outputs and "
                "avoid using them as the sole basis for "
                "critical business decisions.\n"
                "========================================\n"
            )

        #
        # SEC004 Timestamp Dependency
        #
        if "now(" in clean_code:
            score -= 10
            findings += 1
            low_count += 1

            report += (
                "\n"
                "========================================\n"
                "LOW RISK\n\n"
                "Issue:\n"
                "Timestamp Dependency\n\n"
                "Explanation:\n"
                "The contract relies on the current "
                "timestamp during execution.\n\n"
                "Impact:\n"
                "Time based logic may behave differently "
                "depending on when the contract is "
                "executed.\n\n"
                "Recommendation:\n"
                "Avoid using timestamps as the only "
                "factor for critical decisions.\n"
                "========================================\n"
            )

        #
        # SEC005 Transaction Time Dependency
        #
        if "created(" in clean_code:
            score -= 10
            findings += 1
            low_count += 1

            report += (
                "\n"
                "========================================\n"
                "LOW RISK\n\n"
                "Issue:\n"
                "Transaction Time Dependency\n\n"
                "Explanation:\n"
                "The contract relies on transaction "
                "creation time.\n\n"
                "Impact:\n"
                "Contract behaviour may vary depending "
                "on when a transaction was created.\n\n"
                "Recommendation:\n"
                "Avoid relying exclusively on transaction "
                "time for critical business logic.\n"
                "========================================\n"
            )

        #
        # SEC006 Unbounded Storage Growth
        #
        if "self.trail +=" in clean_code:
            score -= 20
            findings += 1
            medium_count += 1

            report += (
                "\n"
                "========================================\n"
                "MEDIUM RISK\n\n"
                "Issue:\n"
                "Unbounded Storage Growth\n\n"
                "Explanation:\n"
                "A storage variable appears to grow "
                "continuously without limits.\n\n"
                "Impact:\n"
                "Contract storage may increase over "
                "time, resulting in higher storage "
                "costs and reduced efficiency.\n\n"
                "Recommendation:\n"
                "Implement limits, pruning mechanisms, "
                "or cleanup routines to control storage "
                "growth.\n"
                "========================================\n"
            )

        #
        # SEC007 Access Control (Menggunakan clean_code)
        #
        has_write_method = "@gl.public.write" in clean_code

        has_owner_or_admin = (
            "owner:" in clean_code or
            "self.owner" in clean_code or
            "admin:" in clean_code or
            "self.admin" in clean_code
        )

        has_access_validation = (
            "!= self.owner" in clean_code or
            "== self.owner" in clean_code or
            "!= self.admin" in clean_code or
            "== self.admin" in clean_code
        )

        if (
            has_write_method and
            not (has_owner_or_admin and has_access_validation)
        ):
            score -= 30
            findings += 1
            high_count += 1

            report += (
                "\n"
                "========================================\n"
                "HIGH RISK\n\n"
                "Issue:\n"
                "Missing Access Control\n\n"
                "Explanation:\n"
                "A public write method was detected but "
                "no owner or admin validation was found.\n\n"
                "Impact:\n"
                "Unauthorized users may be able to modify "
                "the contract state.\n\n"
                "Recommendation:\n"
                "Add owner or admin validation before "
                "allowing state changes.\n\n"
                "Example:\n"
                "if caller != self.owner:\n"
                "    raise Exception('Unauthorized')\nor\n\n"
                "if caller != self.admin:\n"
                "    raise Exception('Unauthorized')\n"
                "========================================\n"
            )

        #
        # SEC008 External Web Access
        #
        if "gl.nondet.web.get(" in clean_code:
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "External Web Access (GET)\n\n"
                "Explanation:\n"
                "The contract retrieves information from "
                "an external website.\n\n"
                "Impact:\n"
                "Contract behaviour may depend on "
                "third party data sources outside "
                "blockchain control.\n\n"
                "Recommendation:\n"
                "Validate and verify external data "
                "before using it in critical logic.\n"
                "========================================\n"
            )

        if "gl.nondet.web.render(" in clean_code:
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "External Web Access (RENDER)\n\n"
                "Explanation:\n"
                "The contract renders external web "
                "content before processing it.\n\n"
                "Impact:\n"
                "Website changes may affect the "
                "behaviour and output of the contract.\n\n"
                "Recommendation:\n"
                "Use trusted sources and validate "
                "all retrieved content.\n"
                "========================================\n"
            )

        #
        # SEC009 LLM Usage Detection
        #
        if "gl.nondet.llm" in clean_code:
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "LLM Usage Detected\n\n"
                "Explanation:\n"
                "The contract uses a Large Language Model.\n\n"
                "Impact:\n"
                "Outputs may vary depending on prompts,\n"
                "model versions and execution context.\n\n"
                "Recommendation:\n"
                "Validate AI generated responses before\n"
                "using them in important decisions.\n"
                "========================================\n"
            )

        if "exec_prompt(" in clean_code:
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "Prompt Execution Detected\n\n"
                "Explanation:\n"
                "The contract sends prompts to an AI model.\n\n"
                "Impact:\n"
                "Different prompts may produce different\n"
                "results and behaviours.\n\n"
                "Recommendation:\n"
                "Review prompts regularly and validate\n"
                "generated outputs.\n"
                "========================================\n"
            )

        if "llm_call" in clean_code:
            findings += 1
            info_count += 1

            report += (
                "\n"
                "========================================\n"
                "INFO\n\n"
                "Issue:\n"
                "LLM Interaction Detected\n\n"
                "Explanation:\n"
                "The contract interacts with a language model.\n\n"
                "Impact:\n"
                "Responses may vary depending on context,\n"
                "model behaviour and prompt design.\n\n"
                "Recommendation:\n"
                "Do not rely solely on AI output without\n"
                "additional validation.\n"
                "========================================\n"
            )

        #
        # SEC010 Excessive LLM Dependence
        #
        llm_usage_count = (
            clean_code.count("gl.nondet.llm") +
            clean_code.count("exec_prompt(") +
            clean_code.count("llm_call")
        )

        if llm_usage_count >= 5:
            score -= 15
            findings += 1
            medium_count += 1
            report += (
                "\n"
                "========================================\n"
                "MEDIUM RISK\n\n"
                "Issue:\n"
                "Excessive LLM Dependence\n\n"
                "Explanation:\n"
                "The contract relies heavily on AI generated outputs.\n\n"
                "Impact:\n"
                "Business logic may become difficult to audit,\n"
                "predict, and reproduce consistently.\n\n"
                "Recommendation:\n"
                "Reduce AI involvement in critical state-changing\n"
                "operations and validate AI responses.\n\n"
                "AI Usage Count:\n"
                + str(llm_usage_count)
                + "\n========================================\n"
            )
        elif llm_usage_count >= 2:
            score -= 10
            findings += 1
            low_count += 1
            report += (
                "\n"
                "========================================\n"
                "LOW RISK\n\n"
                "Issue:\n"
                "Increased AI Dependence\n\n"
                "Explanation:\n"
                "The contract uses multiple AI interactions.\n\n"
                "Impact:\n"
                "Business logic may become harder to\n"
                "audit and reproduce consistently.\n\n"
                "Recommendation:\n"
                "Review whether every AI call is necessary\n"
                "and validate outputs.\n\n"
                "AI Usage Count:\n"
                + str(llm_usage_count)
                + "\n========================================\n"
            )

        #
        # SEC011 Unvalidated External Response
        #
        has_external_response = (
            "gl.nondet.llm" in clean_code or
            "exec_prompt(" in clean_code or
            "gl.nondet.web.get(" in clean_code or
            "gl.nondet.web.render(" in clean_code or
            "gl.contract.get_at(" in clean_code
        )

        has_validation = (
            "require(" in clean_code or
            "require (" in clean_code or
            "raise Exception" in clean_code or
            "assert " in clean_code or
            "assert(" in clean_code or
            "json.loads(" in clean_code or
            "parse_json" in clean_code or
            "int(" in clean_code or
            "float(" in clean_code or
            "bool(" in clean_code
        )

        has_decision_logic = (
            "if " in clean_code or
            "elif " in clean_code or
            "while " in clean_code
        )

        has_critical_state_update = (
            ("self." in clean_code and "=" in clean_code) and
            not ("self.score" in clean_code or "self.findings" in clean_code)
        )

        if (
            has_external_response and
            (has_decision_logic or has_critical_state_update) and
            not has_validation
        ):
            score -= 15
            findings += 1
            medium_count += 1

            report += (
                "\n"
                "========================================\n"
                "MEDIUM RISK\n\n"
                "Issue:\n"
                "Unvalidated External Response (Strict Check)\n\n"
                "Explanation:\n"
                "The contract consumes external data (Web, LLM, or Cross-Contract) "
                "and uses it in conditional logic or state updates without "
                "prior validation, type casting, or sanitization.\n\n"
                "Impact:\n"
                "Unsanitized or malicious external payloads can manipulate "
                "contract execution flow and corrupt state integrity.\n\n"
                "Recommendation:\n"
                "Always validate, parse (e.g., json.loads), or type-cast (e.g., int) "
                "external responses before utilizing them in critical operations.\n"
                "========================================\n"
            )

        #
        # Score Floor
        #
        if score < 0:
            score = 0

        #
        # Risk Classification
        #
        if score >= 80:
            risk = "LOW"
        elif score >= 50:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        header = (
            "\n"
            "========================================\n"
            "GENLAYER SECURITY REPORT\n\n"
            "Security Score : " + str(score) + "\n"
            "Risk Level     : " + risk + "\n"
            "Total Findings : " + str(findings) + "\n"
            "========================================\n"
        )

        summary = (
            "\n"
            "========================================\n"
            "EXECUTIVE SUMMARY\n"
            "========================================\n\n"
            "High Risk Findings   : " + str(high_count) + "\n"
            "Medium Risk Findings : " + str(medium_count) + "\n"
            "Low Risk Findings    : " + str(low_count) + "\n"
            "Info Findings        : " + str(info_count) + "\n\n"
            "Audit Engine Version : " + self.audit_version + "\n"
            "========================================\n"
        )

        report = header + summary + report

        self.high_count = u256(high_count)
        self.medium_count = u256(medium_count)
        self.low_count = u256(low_count)
        self.info_count = u256(info_count)

        self.score = u256(score)
        self.findings_count = u256(findings)
        self.risk_level = risk
        self.findings = report

    @gl.public.view
    def get_high_count(self) -> u256:
        return self.high_count

    @gl.public.view
    def get_medium_count(self) -> u256:
        return self.medium_count

    @gl.public.view
    def get_low_count(self) -> u256:
        return self.low_count

    @gl.public.view
    def get_info_count(self) -> u256:
        return self.info_count

    @gl.public.view
    def get_score(self) -> u256:
        return self.score

    @gl.public.view
    def get_findings_count(self) -> u256:
        return self.findings_count

    @gl.public.view
    def get_risk_level(self) -> str:
        return self.risk_level

    @gl.public.view
    def get_findings(self) -> str:
        return self.findings
