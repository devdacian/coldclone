# Prior art

## cloneguard (inspiration for the prompt-injection scanner)

coldclone's host-side prompt-injection content scanner (`scan_injection` in
`sanitize_repo.py`) draws its **category taxonomy** from
[cloneguard](https://github.com/prodnull/cloneguard) (Apache-2.0), which we
credit here as inspiration.

What we took: the *idea* of organizing prompt-injection signal into named
categories — `instruction_override`, `reasoning_hijack`, `mcp_tool_poisoning`,
`exfil_imperative`, `viral_propagation`, `behavioral_manipulation`,
`memory_poisoning`, `authority_impersonation`, `encoding_obfuscation`,
`markdown_svg_injection`, `terminal_escape` — plus the general public-research
framing of LLM prompt-injection threats (e.g. indirect-prompt-injection
literature and public security write-ups). We added one net-new category for
the security-review use case: **`audit_verdict_manipulation`** (content
engineered to corrupt a security verdict).

What we did NOT take: any verbatim rule text, YAML rule files, regex patterns,
or code. coldclone's threat model is different — a **static, host-side,
pre-scan** of an untrusted repo before a human or an auditor-LLM opens it, not
a runtime guard for a live coding agent — so our rule corpus, halt/warn tiering
(ScanMode), and fail-open posture are independently authored. The rules in
`INJECTION_RULES` are original work, MIT-licensed under coldclone's own
[LICENSE](LICENSE).

Because nothing is copied verbatim, coldclone carries no Apache-2.0 NOTICE
obligation and stays cleanly MIT. This credit is a courtesy to cloneguard's
authors for the conceptual inspiration.
