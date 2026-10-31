package ui

// opAction is one power action as the Power ▾ menu lists it: a link to its confirm page
// (Href), or disabled with the reason (Why). The Operations tab that used to list these
// was retired in round-2 slice C (plan 04 §11 item 8): the actions live in the server
// header's Power menu on every tab.
type opAction struct {
	Label, Detail, Why string
	Href               string
	Forced             bool
}

// notSetUp explains a feature whose service this installation did not wire.
const notSetUp = "Not set up in this installation."

// withWhy returns copies of actions, each disabled with reason why.
func withWhy(actions []opAction, why string) []opAction {
	out := make([]opAction, len(actions))
	for i, a := range actions {
		a.Why = why
		out[i] = a
	}
	return out
}
