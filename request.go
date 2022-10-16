package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	ipv4Address uint8 = 1 + iota
	_
	fqdnAddress
	ipv6Address
)

const (
	ConnectCommand uint8 = 1 + iota
	BindCommand
	AssociateCommand
)

const udpBufSize = 64 * 1024

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	//AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

type DNSResolver struct{}

func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}

func (s *Server) handleRequest(req *Request, conn net.Conn) error {
	ctx := context.Background()

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		resolver := &DNSResolver{}
		ctx_, addr, err := resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, uint8(hostUnreachable), nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = ctx_
		dest.IP = addr
	}

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, uint8(commandNotSupported), nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil, fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != Version5 {
		return nil, fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  Version5,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = Version5
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn net.Conn, req *Request) error {

	dial := func(ctx context.Context, net_, addr string) (net.Conn, error) {
		return net.Dial(net_, addr)
	}
	target, err := dial(ctx, "tcp", req.DestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, uint8(resp), nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, uint8(succeeded), &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.bufConn, errCh)
	go proxy(conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

// handleBind is used to handle a connect command
// bind expected that client have use connect to establish a primary connection
// but it's not properly to record the connection's ip and port  and verify bind command have primary connection first
// you just can distinguish which connection is the primary connection for bind for there may be other connections serving
// other users when clients using a same router, in which case all have the same ip
func (s *Server) handleBind(ctx context.Context, conn net.Conn, req *Request) error {
	// todo do it when initialization
	publicIP := net.ParseIP(s.cfg.ip)
	if publicIP == nil || publicIP.IsPrivate() {
		return errors.New("invalid config,not a valid public ip")
	}

	bl, err := tcpListenerForBind()
	if err != nil {
		if err := sendReply(conn, uint8(commandNotSupported), nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return err
	}
	defer bl.Close()

	local := bl.Addr().(*net.TCPAddr)
	bind := AddrSpec{IP: publicIP, Port: local.Port}
	if err := sendReply(conn, uint8(succeeded), &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conChan := make(chan net.Conn)
	go func() {
		for {
			bconn, err := bl.Accept()
			// should reject connection if not from de ip bind command specify
			if string(bconn.RemoteAddr().(*net.TCPAddr).IP) != string(req.DestAddr.IP) {
				bconn.Close()
				bconn = nil
				continue
			}

			if err != nil {
				conChan <- nil
				return
			}
			conChan <- bconn
		}
	}()
	timeOut := false
	var bconn net.Conn
	select {
	case <-ctx.Done():
		timeOut = true
	case bconn = <-conChan:
	}

	if timeOut {
		if err := sendReply(conn, uint8(TTLExpired), nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return errors.New("no connection is established")
	}
	if bconn != nil {
		local := bconn.RemoteAddr().(*net.TCPAddr)
		bind := AddrSpec{IP: local.IP, Port: local.Port}
		if err := sendReply(conn, uint8(succeeded), &bind); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(bconn, conn, errCh)
	go proxy(conn, bconn, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}

	if err := sendReply(conn, uint8(commandNotSupported), nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// see https://levelup.gitconnected.com/listening-to-random-available-port-in-go-3541dddbb0c5?gi=aec26305b732
func tcpListenerForBind() (net.Listener, error) {
	return net.Listen("tcp", ":0")
}

func udpListenerForBind() (net.PacketConn, error) {
	return net.ListenPacket("udp", ":0")
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	// todo do it when initialization
	publicIP := net.ParseIP(s.cfg.ip)
	if publicIP == nil || publicIP.IsPrivate() {
		return errors.New("invalid config,not a valid public ip")
	}
	localUdpConn, err := udpListenerForBind()
	if err != nil {
		if err := sendReply(conn, uint8(commandNotSupported), nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return err
	}

	defer localUdpConn.Close()

	laddr := localUdpConn.(*net.UDPConn).LocalAddr().(*net.UDPAddr)

	bind := AddrSpec{IP: publicIP, Port: laddr.Port}
	if err := sendReply(conn, uint8(succeeded), &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	buf := make([]byte, udpBufSize)

	for {
		n, addr, err := localUdpConn.ReadFrom(buf)
		uaddr := addr.(*net.UDPAddr)
		if err != nil {
			continue
		}
		if uaddr.IP.String() != req.RemoteAddr.IP.String() || uaddr.IP.String() != req.DestAddr.IP.String() {
			// handle packets except from the IP handle associate specified
			continue
		}
		if uaddr.IP.String() == req.RemoteAddr.IP.String() {
			_, err = localUdpConn.WriteTo(buf[:n], &net.UDPAddr{IP: req.DestAddr.IP, Port: req.DestAddr.Port})
			if err != nil {
				if err := sendReply(conn, uint8(commandNotSupported), nil); err != nil {
					return fmt.Errorf("Failed to send reply: %v", err)
				}
				return err
			}
		} else {
			_, err = localUdpConn.WriteTo(buf[:n], &net.UDPAddr{IP: req.RemoteAddr.IP, Port: req.RemoteAddr.Port})
			if err != nil {
				continue
			}
		}
	}
	//if err := sendReply(conn, uint8(commandNotSupported), nil); err != nil {
	//	return fmt.Errorf("Failed to send reply: %v", err)
	//}
}
