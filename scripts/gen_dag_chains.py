#!/usr/bin/env python3
"""Generate pkg/chain/dag_chains.go with deep dependency chains, ATT&CK phases, conditions, and fallbacks."""

import os

OUTFILE = os.path.join(os.path.dirname(__file__), "..", "pkg", "chain", "dag_chains.go")

# Each node: (id, name, category, phase, depends_on, condition, fallback_for, severity, execute_body)
# condition: None | "any" | "crit_high" | "category:xxx"
# fallback_for: 0 means none

NODES = [
    # === Layer 0: Reconnaissance ===
    (0, "Platform Fingerprint", "recon", "PhaseRecon", [], None, 0, "",
     'exploit.PlatformFingerprint(t, exploit.PlatformFingerprintConfig{Timeout: c.Timeout})'),
    (13, "CORS Bypass", "config", "PhaseRecon", [], None, 0, "",
     'exploit.CORSBypassCheck(t, exploit.CORSBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (17, "WS Hijack", "transport", "PhaseRecon", [], None, 0, "",
     'exploit.WSHijackCheck(t, exploit.WSHijackConfig{Token: c.Token, Timeout: c.Timeout})'),
    (35, "Auth Mode Abuse", "auth", "PhaseRecon", [], None, 0, "",
     'exploit.AuthModeAbuseCheck(t, exploit.AuthModeConfig{Token: c.Token, Timeout: c.Timeout})'),

    # === Layer 1: Initial Access & Early Credential Harvesting ===
    (1, "SSRF", "ssrf", "PhaseInitAccess", [0], None, 0, "",
     'exploit.SSRFCheck(t, exploit.SSRFConfig{Token: c.Token, Timeout: c.Timeout, CallbackURL: c.CallbackURL})'),
    (2, "Eval Injection", "injection", "PhaseInitAccess", [0], None, 0, "",
     'exploit.EvalInjectCheck(t, exploit.EvalInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (3, "API Key Steal", "credential", "PhaseCredAccess", [0], None, 0, "",
     'exploit.APIKeyStealCheck(t, exploit.APIKeyStealConfig{Token: c.Token, Timeout: c.Timeout})'),
    (4, "Pairing Brute", "auth", "PhaseInitAccess", [0, 35], None, 0, "",
     'cfg := exploit.DefaultPairingBruteConfig(); cfg.Token = c.Token; cfg.Timeout = c.Timeout; return exploit.PairingBruteCheck(t, cfg)'),
    (6, "Prompt Injection", "injection", "PhaseInitAccess", [0], None, 0, "",
     'exploit.PromptInjectCheck(t, exploit.PromptInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (15, "Log Disclosure", "disclosure", "PhaseRecon", [0], None, 0, "",
     'exploit.LogDisclosureCheck(t, exploit.LogDisclosureConfig{Token: c.Token, Timeout: c.Timeout})'),
    (19, "OAuth Abuse", "auth", "PhaseInitAccess", [0, 35], None, 0, "",
     'exploit.OAuthAbuseCheck(t, exploit.OAuthAbuseConfig{Token: c.Token, Timeout: c.Timeout})'),
    (20, "Responses API Exploit", "api", "PhaseInitAccess", [0], None, 0, "",
     'exploit.ResponsesExploitCheck(t, exploit.ResponsesExploitConfig{Token: c.Token, Timeout: c.Timeout})'),
    (21, "WS Fuzz", "fuzz", "PhaseInitAccess", [17], "any", 0, "",
     'exploit.WSFuzzCheck(t, exploit.WSFuzzConfig{Token: c.Token, Timeout: c.Timeout})'),
    (31, "MCP Plugin Inject", "injection", "PhaseInitAccess", [0], None, 0, "",
     'exploit.McpInjectCheck(t, exploit.McpInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (32, "ACP Permission Bypass", "auth", "PhaseInitAccess", [0, 35], None, 0, "",
     'exploit.AcpBypassCheck(t, exploit.AcpBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (33, "Unicode Filter Bypass", "injection", "PhaseInitAccess", [0], None, 0, "",
     'exploit.UnicodeBypassCheck(t, exploit.UnicodeBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (36, "Skill Scanner Bypass", "evasion", "PhaseInitAccess", [0], None, 0, "",
     'exploit.SkillScannerBypassCheck(t, exploit.SkillScanBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (38, "Rate Limit Scope Bypass", "auth", "PhaseInitAccess", [0], None, 0, "",
     'exploit.RateLimitBypassCheck(t, exploit.RateLimitBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (42, "CSRF No-Origin Bypass", "config", "PhaseInitAccess", [13], "any", 0, "",
     'exploit.CSRFNoOriginCheck(t, exploit.CSRFBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (43, "Origin Wildcard Check", "config", "PhaseInitAccess", [13], None, 0, "",
     'exploit.OriginWildcardCheck(t, exploit.OriginWildcardConfig{Token: c.Token, Timeout: c.Timeout})'),
    (50, "Link Template Injection", "injection", "PhaseInitAccess", [0], None, 0, "",
     'exploit.LinkTemplateInjectCheck(t, exploit.LinkTemplateInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (51, "QMD Command Injection", "rce", "PhaseExecution", [0], None, 0, "CRITICAL",
     'exploit.QMDCmdInjectCheck(t, exploit.QMDCmdInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (65, "Webhook Signature Verification", "auth", "PhaseInitAccess", [0], None, 0, "HIGH",
     'exploit.WebhookVerifyCheck(t, exploit.WebhookVerifyConfig{Token: c.Token, Timeout: c.Timeout})'),
    (66, "MCP Server List Enumeration", "recon", "PhaseRecon", [0], None, 0, "",
     'exploit.McpServerListCheck(t, exploit.McpInjectConfig{Token: c.Token, Timeout: c.Timeout})'),

    # === Layer 2: Execution & Deeper Credential Access ===
    (7, "RCE Check", "rce", "PhaseExecution", [2], "any", 0, "CRITICAL",
     'exploit.RCECheck(t, exploit.RCEConfig{Token: c.Token, Timeout: c.Timeout})'),
    (8, "Hook Injection", "injection", "PhaseExecution", [0, 6], None, 0, "",
     'exploit.HookInjectCheck(t, exploit.HookInjectConfig{Token: c.Token, HookToken: c.HookToken, HookPath: c.HookPath, Timeout: c.Timeout})'),
    (9, "Secret Extract", "credential", "PhaseCredAccess", [0, 3], None, 0, "",
     'exploit.SecretExtractCheck(t, exploit.SecretExtractConfig{Token: c.Token, Timeout: c.Timeout})'),
    (10, "Config Tamper", "config", "PhasePersistence", [0], None, 0, "",
     'exploit.ConfigTamperCheck(t, exploit.ConfigTamperConfig{Token: c.Token, Timeout: c.Timeout})'),
    (11, "Tools Invoke", "rce", "PhaseExecution", [0], None, 0, "",
     'exploit.ToolsInvokeCheck(t, exploit.ToolsInvokeConfig{Token: c.Token, Timeout: c.Timeout})'),
    (12, "Session Hijack", "session", "PhaseCredAccess", [0, 19], None, 0, "",
     'exploit.SessionHijackCheck(t, exploit.SessionHijackConfig{Token: c.Token, Timeout: c.Timeout})'),
    (14, "Channel Inject", "injection", "PhaseExecution", [17], None, 0, "",
     'exploit.ChannelInjectCheck(t, exploit.ChannelInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (16, "Patch Escape", "traversal", "PhaseExecution", [0], None, 0, "",
     'exploit.PatchEscapeCheck(t, exploit.PatchEscapeConfig{Token: c.Token, Timeout: c.Timeout})'),
    (18, "Agent Inject", "injection", "PhaseExecution", [6], "any", 0, "",
     'exploit.AgentInjectCheck(t, exploit.AgentInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (39, "Flood Guard Reset", "auth", "PhaseInitAccess", [38], None, 38, "",
     'exploit.FloodGuardResetCheck(t, exploit.FloodGuardConfig{Token: c.Token, Timeout: c.Timeout})'),
    (40, "Silent Local Pairing", "auth", "PhaseInitAccess", [4], "any", 0, "",
     'exploit.SilentPairCheck(t, exploit.SilentPairConfig{Token: c.Token, Timeout: c.Timeout})'),
    (41, "Auth Disable Leak", "auth", "PhaseCredAccess", [35], "any", 0, "",
     'exploit.AuthDisableLeakCheck(t, exploit.AuthDisableConfig{Token: c.Token, Timeout: c.Timeout})'),
    (55, "OAuth Token Theft", "credential", "PhaseCredAccess", [19], "any", 0, "HIGH",
     'exploit.OAuthTokenTheftCheck(t, exploit.OAuthTokenTheftConfig{Token: c.Token, Timeout: c.Timeout})'),
    (56, "ClawJacked Token Theft", "credential", "PhaseCredAccess", [17], None, 0, "CRITICAL",
     'exploit.ClawJackedCheck(t, exploit.WSHijackConfig{Token: c.Token, Timeout: c.Timeout})'),
    (57, "Gateway URL SSRF", "ssrf", "PhaseInitAccess", [1], None, 1, "",
     'exploit.GatewayURLSSRFCheck(t, exploit.GatewayURLSSRFConfig{Token: c.Token, Timeout: c.Timeout})'),
    (58, "Browser Upload Traversal", "traversal", "PhaseExecution", [0], None, 0, "CRITICAL",
     'exploit.BrowserUploadTraversalCheck(t, exploit.BrowserUploadTraversalConfig{Token: c.Token, Timeout: c.Timeout})'),
    (59, "Keychain Cmd Inject", "rce", "PhaseExecution", [0], None, 0, "CRITICAL",
     'exploit.KeychainCmdInjectCheck(t, exploit.KeychainCmdInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (63, "Bypass Soul Parameter Injection", "auth", "PhaseInitAccess", [0], None, 0, "CRITICAL",
     'exploit.BypassSoulCheck(t, exploit.BypassSoulConfig{Token: c.Token, Timeout: c.Timeout})'),

    # === Layer 3: Lateral Movement & Collection ===
    (5, "Cron Bypass", "persistence", "PhasePersistence", [0, 10], "any", 0, "",
     'exploit.CronBypassCheck(t, exploit.CronBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (22, "Agent File Inject", "persistence", "PhasePersistence", [18], "any", 0, "",
     'exploit.AgentFileInjectCheck(t, exploit.AgentFileInjectConfig{Token: c.Token, Timeout: c.Timeout})'),
    (23, "Session File Write", "traversal", "PhasePersistence", [12], "any", 0, "",
     'exploit.SessionFileWriteCheck(t, exploit.SessionFileWriteConfig{Token: c.Token, Timeout: c.Timeout})'),
    (24, "Approval Hijack", "auth", "PhaseExecution", [7], "any", 0, "",
     'exploit.ApprovalHijackCheck(t, exploit.ApprovalHijackConfig{Token: c.Token, Timeout: c.Timeout})'),
    (25, "Talk Secrets", "credential", "PhaseCredAccess", [9], "any", 0, "",
     'exploit.TalkSecretsCheck(t, exploit.TalkSecretsConfig{Token: c.Token, Timeout: c.Timeout})'),
    (26, "Browser Request SSRF", "ssrf", "PhaseLateral", [1], "any", 0, "",
     'exploit.BrowserRequestCheck(t, exploit.BrowserRequestConfig{Token: c.Token, Timeout: c.Timeout})'),
    (27, "Secrets Resolve", "credential", "PhaseCredAccess", [9], "any", 0, "",
     'exploit.SecretsResolveCheck(t, exploit.SecretsResolveConfig{Token: c.Token, Timeout: c.Timeout})'),
    (28, "Transcript Theft", "disclosure", "PhaseCollection", [12], "any", 0, "",
     'exploit.TranscriptTheftCheck(t, exploit.TranscriptTheftConfig{Token: c.Token, Timeout: c.Timeout})'),
    (29, "Rogue Node", "persistence", "PhasePersistence", [4], "any", 0, "",
     'exploit.RogueNodeCheck(t, exploit.RogueNodeConfig{Token: c.Token, Timeout: c.Timeout})'),
    (44, "SSRF DNS Rebinding", "ssrf", "PhaseLateral", [1], "any", 0, "",
     'exploit.SSRFRebindCheck(t, exploit.SSRFRebindConfig{Token: c.Token, Timeout: c.Timeout})'),
    (45, "SSRF Proxy Bypass", "ssrf", "PhaseLateral", [1], "any", 0, "",
     'exploit.SSRFProxyBypassCheck(t, exploit.SSRFProxyConfig{Token: c.Token, Timeout: c.Timeout})'),
    (49, "Redaction Pattern Bypass", "disclosure", "PhaseCollection", [15], "any", 0, "",
     'exploit.RedactBypassCheck(t, exploit.RedactBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (52, "Exec Race TOCTOU", "rce", "PhaseExecution", [7], "any", 0, "CRITICAL",
     'exploit.ExecRaceTOCTOUCheck(t, exploit.ExecRaceTOCTOUConfig{Token: c.Token, Timeout: c.Timeout})'),
    (53, "Hidden Content Discovery", "disclosure", "PhaseCollection", [0, 15], None, 0, "",
     'exploit.HiddenContentCheck(t, exploit.HiddenContentConfig{Token: c.Token, Timeout: c.Timeout})'),
    (54, "Memory Data Leak", "disclosure", "PhaseCollection", [12], "any", 0, "",
     'exploit.MemoryDataLeakCheck(t, exploit.MemoryDataLeakConfig{Token: c.Token, Timeout: c.Timeout})'),
    (60, "Cron Webhook SSRF", "ssrf", "PhaseLateral", [5], "any", 0, "",
     'exploit.CronWebhookSSRFCheck(t, exploit.CronWebhookSSRFConfig{Token: c.Token, Timeout: c.Timeout})'),

    # === Layer 4: Deep Exploitation & Privilege Escalation ===
    (34, "Secret Exec Abuse", "credential", "PhaseExecution", [9, 27], "any", 0, "",
     'exploit.SecretExecAbuseCheck(t, exploit.SecretExecConfig{Token: c.Token, Timeout: c.Timeout})'),
    (46, "Obfuscation Unicode Bypass", "evasion", "PhaseExecution", [7, 33], "crit_high", 0, "",
     'exploit.ObfuscationBypassCheck(t, exploit.ObfuscationBypassConfig{Token: c.Token, Timeout: c.Timeout})'),
    (47, "Exec Socket Leak", "disclosure", "PhaseCollection", [7], "any", 0, "",
     'exploit.ExecSocketLeakCheck(t, exploit.ExecSocketConfig{Token: c.Token, Timeout: c.Timeout})'),
    (48, "Marker Spoof + Skill Evasion", "evasion", "PhaseExecution", [33, 36], "any", 0, "",
     'exploit.MarkerSpoofCheck(t, exploit.MarkerSpoofConfig{Token: c.Token, Timeout: c.Timeout})'),
    (61, "Skill Poison", "injection", "PhasePersistence", [18, 36], "any", 0, "CRITICAL",
     'exploit.SkillPoisonCheck(t, exploit.SkillPoisonConfig{Token: c.Token, Timeout: c.Timeout})'),
    (62, "Media SSRF", "ssrf", "PhaseLateral", [1, 26], "any", 0, "",
     'exploit.MediaSSRFCheck(t, exploit.MediaSSRFConfig{Token: c.Token, Timeout: c.Timeout})'),

    # === Layer 5: Full Kill Chain ===
    (30, "Full RCE Chain", "rce", "PhaseExecution", [7, 24], "crit_high", 0, "CRITICAL",
     'exploit.FullRCECheck(t, exploit.FullRCEConfig{Token: c.Token, Timeout: c.Timeout})'),

    # === Layer 6: Exfiltration & Impact ===
    (64, "C2 Exfiltration via Command Filter", "rce", "PhaseExfil", [30], "any", 0, "CRITICAL",
     'exploit.C2ExfilCheck(t, exploit.C2ExfilConfig{Token: c.Token, Timeout: c.Timeout})'),
]

CONDITION_MAP = {
    "any": "func(f []utils.Finding) bool { return HasAnyFinding(f) }",
    "crit_high": "func(f []utils.Finding) bool { return HasCriticalOrHigh(f) }",
}

def gen_node(n):
    nid, name, cat, phase, deps, cond, fallback, sev, body = n
    lines = []
    lines.append("\tdag.AddNode(&ChainNode{")
    lines.append(f"\t\tID:       {nid},")
    lines.append(f'\t\tName:     "{name}",')
    lines.append(f'\t\tCategory: "{cat}",')
    lines.append(f"\t\tPhase:    {phase},")
    if deps:
        dep_str = ", ".join(str(d) for d in deps)
        lines.append(f"\t\tDependsOn: []int{{{dep_str}}},")
    if cond:
        lines.append(f"\t\tCondition: {CONDITION_MAP[cond]},")
    if fallback:
        lines.append(f"\t\tFallbackFor: {fallback},")
    if sev:
        lines.append(f'\t\tSeverity: "{sev}",')

    # Handle special multi-statement execute bodies
    if body.startswith("cfg :="):
        # Multi-statement: split on "; "
        stmts = body.split("; ")
        lines.append("\t\tExecute: func(t utils.Target, c ChainConfig) []utils.Finding {")
        for s in stmts[:-1]:
            lines.append(f"\t\t\t{s}")
        lines.append(f"\t\t\t{stmts[-1]}")
        lines.append("\t\t},")
    else:
        lines.append("\t\tExecute: func(t utils.Target, c ChainConfig) []utils.Finding {")
        lines.append(f"\t\t\treturn {body}")
        lines.append("\t\t},")

    lines.append("\t})")
    return "\n".join(lines)


def main():
    # Group by layer comment
    layers = {
        0: "Layer 0: Reconnaissance (zero-auth, no dependencies)",
        1: "Layer 1: Initial Access & Early Credential Harvesting",
        2: "Layer 2: Execution & Deeper Credential Access",
        3: "Layer 3: Lateral Movement & Collection",
        4: "Layer 4: Deep Exploitation & Privilege Escalation",
        5: "Layer 5: Full Kill Chain",
        6: "Layer 6: Exfiltration & Impact",
    }

    # Assign layer based on position in NODES list
    layer_breaks = [4, 26, 42, 55, 61, 62, 63]  # indices where new layers start
    def get_layer(idx):
        for li, brk in enumerate(layer_breaks):
            if idx < brk:
                return li
        return len(layer_breaks)

    out = []
    out.append("package chain")
    out.append("")
    out.append("import (")
    out.append('\t"github.com/coff0xc/lobster-guard/pkg/exploit"')
    out.append('\t"github.com/coff0xc/lobster-guard/pkg/utils"')
    out.append(")")
    out.append("")
    out.append("// BuildFullDAG creates the complete 66-node DAG with deep dependencies, conditions,")
    out.append("// ATT&CK phases, and fallback paths. Max depth: 7 layers.")
    out.append("func BuildFullDAG(concurrency int, aggressive bool) *DAGChain {")
    out.append("\tdag := NewDAGChain(concurrency, aggressive)")

    current_layer = -1
    for idx, node in enumerate(NODES):
        layer = get_layer(idx)
        if layer != current_layer:
            current_layer = layer
            comment = layers.get(layer, f"Layer {layer}")
            out.append("")
            out.append(f"\t// {'=' * 68}")
            out.append(f"\t//  {comment}")
            out.append(f"\t// {'=' * 68}")

        out.append("")
        out.append(gen_node(node))

    out.append("")
    out.append("\treturn dag")
    out.append("}")
    out.append("")
    out.append("// RunDAGChain executes the full DAG attack chain (v2 replacement for RunFullChain)")
    out.append("func RunDAGChain(target utils.Target, cfg ChainConfig, concurrency int, aggressive bool) []utils.Finding {")
    out.append("\tdag := BuildFullDAG(concurrency, aggressive)")
    out.append("\treturn dag.Execute(target, cfg)")
    out.append("}")
    out.append("")

    with open(OUTFILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))

    print(f"Generated {OUTFILE} with {len(NODES)} nodes")


if __name__ == "__main__":
    main()
