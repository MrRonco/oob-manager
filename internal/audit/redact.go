package audit

import "strings"

// Redacted replaces secret values in audit params.
const Redacted = "[redacted]"

// redact returns a copy of p with secret-looking values replaced by Redacted, at any
// depth. Callers should never pass secrets; this is the fail-closed backstop, so a
// password, TOTP secret, raw token, one-time code or enrolment link can never reach
// the chain or Graylog. The caller's map is not modified.
func redact(p map[string]any) map[string]any {
	if p == nil {
		return nil
	}
	out := make(map[string]any, len(p))
	for k, v := range p {
		if secretKey(k) {
			out[k] = Redacted
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

// redactValue descends into maps and lists, so a secret inside a list of maps is caught
// too (fuzzing found that only nested maps were). Other values are returned as they are.
func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return redact(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactValue(e)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i, m := range x {
			out[i] = redact(m)
		}
		return out
	default:
		return v
	}
}

// secretKey matches keys that name secrets. "token_id" and the like stay readable.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	for _, part := range []string{"password", "secret", "passphrase", "private"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	switch k {
	case "token", "raw_token", "code", "totp", "link", "uri", "url", "otpauth":
		return true
	}
	return false
}
