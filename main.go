package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"socks-proxy/auth"
)

type port uint16

const defaultPort port = 1080

/**
https://www.rfc-editor.org/rfc/rfc1928
1. 第一阶段建立tcp链接,sock服务器默认端口是1080

2. 进入协商阶段
2.1 客户端构造信息发送给服务器
2.1 服务器返回验证方法
2.3 客户端构造验证信息
2.4 服务器返回验证成功失败

3. 发送命令connect,bind,associate
*/

type ServerConfig struct {
	ip string
	p  port
}

func main() {
	s, err := NewServer(ServerConfig{
		ip: "0.0.0.0",
		p:  defaultPort,
	})
	if err != nil {
		log.Fatal("listen failed", err)
	}
	if err := s.ListenAndServe(); err != nil {
		log.Panic(err)
	}
}

type authCollector struct {
	authMap map[auth.AuthMethod]auth.Authenticator
}

func (ac *authCollector) selectMethod(methods []byte) (auth.AuthMethod, auth.Authenticator) {
	if len(ac.authMap) == 0 {
		return auth.AuthMethodNoAcceptableMethods, nil
	}
	for _, mth := range methods {
		am := auth.AuthMethod(mth)
		if authenticator, ok := ac.authMap[am]; ok {
			return am, authenticator
		}
	}
	return auth.AuthMethodNoAcceptableMethods, nil
}

func newAuthCollector() authCollector {
	ac := authCollector{authMap: make(map[auth.AuthMethod]auth.Authenticator)}
	passAuth, _ := auth.NewAuthenticator(auth.AuthMethodUsernamePassword)
	ac.authMap[auth.AuthMethodUsernamePassword] = passAuth
	return ac
}

type Server struct {
	cfg ServerConfig
	l   net.Listener
	ac  authCollector
}

func (s *Server) ListenAndServe() error {
	err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve()
}

func (s *Server) Listen() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ip, s.cfg.p)
	// socks5协议需要同时支持ipv4和ipv6
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Println(err)
		ln, err = net.Listen("tcp6", addr)
	}
	if err != nil {
		return err
	}
	s.l = ln
	return nil
}

func (s *Server) Serve() error {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) error {
	defer conn.Close()

	bufConn := bufio.NewReader(conn)

	err := s.authenticate(conn, bufConn)
	if err != nil {
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, uint8(addressNotSupported), nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		return err
	}

	return nil
}

func NewServer(cfg ServerConfig) (*Server, error) {
	return &Server{
		cfg: cfg,
		ac:  newAuthCollector(),
	}, nil
}
