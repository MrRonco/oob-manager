// Package console is the graphical console broker (docs/tech_doc.md §18): one-time
// WebSocket tickets, one active console per server, the RFB relay between the browser
// (noVNC) and the BMC's VNC server, idle/maximum timeouts, the harmless RFB banner
// probe used for feature detection, and the audit trail.
//
// The app authenticates to the BMC (VNC DES challenge) and offers the browser security
// type None, so the BMC's VNC password never reaches the browser. Every message the
// browser sends is parsed and allowlisted (package rfb) before it reaches the BMC.
package console
