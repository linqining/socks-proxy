package main

type Command int

// A Reply represents a SOCKS command reply code.
type Reply int

const (
	Version5 = 0x05

	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04

	CmdConnect Command = 0x01 // establishes an active-open forward proxy connection
	cmdBind    Command = 0x02 // establishes a passive-open forward proxy connection

)

const (
	succeeded Reply = 0x00 + iota
	serverFailure
	notAllowedByRuleset
	networkUnreachable
	hostUnreachable
	connectionRefused
	TTLExpired
	commandNotSupported
	addressNotSupported
	// 0x09-0xff unassigned
)
