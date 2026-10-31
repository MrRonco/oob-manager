// Package rfb implements the parts of the RFB (VNC) protocol, RFC 6143, that the
// graphical console relay needs: the client handshake towards a BMC's VNC server (with
// VNC authentication), a server handshake towards the browser that offers only the
// "None" security type, ServerInit parsing, and an allowlisting parser for client to
// server messages.
//
// The relay sits in the middle so that the BMC's VNC password never reaches the
// browser: the app authenticates to the BMC itself and presents an already
// authenticated stream to noVNC.
//
// VNC authentication is DES with a key of at most 8 password bytes (RFC 6143 §7.2.2).
// Anyone who records one challenge/response pair can brute-force the password offline,
// and plain RFB carries everything else (screen, keystrokes) in clear text. Use the
// BMC's TLS-wrapped VNC port on any network that is not fully trusted.
package rfb
