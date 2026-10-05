# The arcaeon verify-before-act gate as an OPA policy (docs/OPA.md). Rego v1 (OPA 1.x).
# input: {"report": <`arcaeon envelope verify` JSON report>, "action": "read" | "act" | "pay" | "irreversible"}
# allow means "these bytes are unchanged and labeled as sealed", never "the content is true".
package arcaeon.gate

allowed := {
	"VERIFIED": {"read", "act", "pay", "irreversible"},
	"COULD NOT LOOK": {"read"},
	"BROKEN": set(),
}

default allow := false

allow if input.action in allowed[input.report.verdict]

default reason := "refused: the report has no verdict this gate knows (missing or unknown)"

reason := sprintf("allowed: %s permits %s", [input.report.verdict, input.action]) if {
	allow
} else := sprintf("refused: unknown action %v", [input.action]) if {
	not input.action in allowed.VERIFIED
} else := "refused: BROKEN refuses every action" if {
	input.report.verdict == "BROKEN"
} else := sprintf("refused: COULD NOT LOOK allows read only, not %s", [input.action]) if {
	input.report.verdict == "COULD NOT LOOK"
}
