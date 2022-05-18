package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

// Start proxy server quic
func startServer() error {
	go func() {
		if err := startServerUDP(); err != nil {
			fmt.Printf("Failed UDP server: %v", err)
		}
	}()

	addr := fmt.Sprintf(":%d", quicPort)
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Printf("Failed accepting client: %v\n", err)
			continue
		}
		// defer session.CloseWithError(0, "done")
		go func() {
			buff := make([]byte, buffSize)
			for {
				stream, err := session.AcceptStream(context.Background())
				if err != nil {
					fmt.Printf("Failed accepting client stream: %v\n", err)
					return
				}
				defer stream.Close()

				n, err := readFromSession(stream, buff)
				if err != nil {
					fmt.Printf("Failed reading from client stream: %v\n", err)
					return
				}
				printDebug("Server got: %s", string(buff[0:n]))

				res, err := udpServerSend(buff[0:n])
				if err != nil {
					fmt.Printf("Failed sending message using UDP: %v", err)
					return
				}

				_, err = stream.Write(res)
				if err != nil {
					fmt.Printf("Failed sending response back to client: %v\n", err)
					return
				}
			}
		}()
	}
}

// Handle proxy UDP server
func startServerUDP() error {
	addr := fmt.Sprintf(":%d", udpPort)

	s, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}

	connection, err := net.ListenUDP("udp4", s)
	if err != nil {
		return err
	}

	defer connection.Close()
	buff := make([]byte, buffSize)

	for {
		n, addr, err := connection.ReadFromUDP(buff)
		if err != nil {
			fmt.Printf("got error reading data from proxy %v\n", err)
			continue
		}
		printDebug("-> %s", string(buff[0:n]))

		res, err := udpServerSend(buff[0:n])
		if err != nil {
			fmt.Printf("Failed to send data through proxy: %v", err)
			continue
		}

		printDebug("data: %s", string(res))
		if _, err = connection.WriteToUDP(res, addr); err != nil {
			fmt.Printf("Failed to send data back to client through udp: %v", err)
			continue
		}
	}
}

// Send proxy's received message to authoritative nameserver
func udpServerSend(msg []byte) ([]byte, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", udpServerPort)
	s, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp4", nil, s)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	_, err = c.Write(msg)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, buffSize)
	n, _, err := c.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[0:n], nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-example"},
	}
}
