//go:build !linux && !darwin

package main

func noEchoFD(int) (func(), error) { return nil, errNotTerminal }

func isTerminalFD(int) bool { return false }
