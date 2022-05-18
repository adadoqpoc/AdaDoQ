package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	dnsgo "github.com/darkoperator/golang-dns"
	quic "github.com/lucas-clemente/quic-go"
)

func readFromSession(stream quic.Stream, buff []byte) (int, error) {
	start := 0
	for {
		n, err := stream.Read(buff[start:])
		start += n
		if n == 0 || err != io.EOF {
			// done
			return start, nil
		}
		if err != nil {
			return start, err
		}
	}
}

var connWindows map[string]*Window
var clientCache *LRUCache

// Handle resolver UDP requests to authoritative nameserver
func startClient() error {
	connWindows = make(map[string]*Window)
	clientCache = InitLRUCache(clientCacheCapacity)
	addr := fmt.Sprintf("127.0.0.1:%d", udpClientPort)

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
			fmt.Printf("got error reading data from resolver %v\n", err)
			continue
		}
		printDebug("-> %s", string(buff[0:n]))

		res, err := clientSend(addr.IP.String(), buff[0:n])
		if err != nil {
			fmt.Printf("Failed to send data through quic: %v", err)
			continue
		}

		printDebug("data: %s", string(res))
		if _, err = connection.WriteToUDP(res, addr); err != nil {
			fmt.Printf("Failed to send data back to client through udp: %v", err)
			continue
		}
	}
}

const _NOTDO = ^byte(1 << 7)

// UnsetDo unsets the DO (DNSSEC OK) bit.
func UnsetDo(rr *dnsgo.OPT) {
	b1 := byte(rr.Hdr.Ttl >> 24)
	b2 := byte(rr.Hdr.Ttl >> 16)
	b3 := byte(rr.Hdr.Ttl >> 8)
	b4 := byte(rr.Hdr.Ttl)
	b3 &= _NOTDO // Unset it
	rr.Hdr.Ttl = uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4)
}

// clears DO bit (if exists)
// return true if exists, false otherwise
func clearDO(msg []byte) ([]byte, bool) {
	req := new(dnsgo.Msg)
	if req.Unpack(msg) != nil {
		// Invalud DNS format
		return msg, false
	}

	ok := false
	for _, rr := range req.Extra {
		if rr.Header().Rrtype == dnsgo.TypeOPT {
			opt := rr.(*dnsgo.OPT)
			if opt.Do() {
				ok = true
				UnsetDo(opt)
			}
		}
	}

	if ok {
		cand, err := req.Pack()
		if err != nil {
			return msg, false
		}
		msg = cand
		return msg, true
	}

	return msg, false
}

func clientSend(ip string, msg []byte) ([]byte, error) {
	msg, isDO := clearDO(msg)
	if !isDO {
		// dnssec do bit is not set, send as UDP
		return udpClientSend(ip, msg)
	}
	w, ok := connWindows[ip]
	if !ok {
		connWindows[ip] = &Window{1, 0, time.Now()}
		return udpClientSend(ip, msg)
	}

	timePassed := time.Since(w.lastUpdate)
	if timePassed < windowSize*time.Second {
		w.curScore++
	} else {
		w.prvScore += (1 - alpha) * w.curScore
		w.prvScore *= math.Pow(alpha, math.Floor(timePassed.Seconds()/windowSize))
		w.lastUpdate = time.Now()
		w.curScore = 1
	}

	printDebug("time passed: %v", timePassed.Seconds())
	score := alpha*w.prvScore + (1-alpha)*w.curScore
	printDebug("score: %v", score)

	printDebug("score2: %v", score)
	if score < threshold {
		session, err := getQuicSession(ip, false)
		if err != nil {
			return udpClientSend(ip, msg)
		}
		resp, err := quicClientSend(ip, msg, session, false)
		if err != nil {
			return udpClientSend(ip, msg)
		}
		return resp, nil
	}
	session, err := getQuicSession(ip, true)
	if err != nil {
		return nil, err
	}
	return quicClientSend(ip, msg, session, true)
}

func clientConnect(ip string) (quic.Session, error) {
	addr := fmt.Sprintf("%s:%d", ip, quicPort)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-example"},
	}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// Send proxy's received message to authoritative nameserver
func udpClientSend(ip string, msg []byte) ([]byte, error) {
	printDebug("Sending UDP")
	addr := fmt.Sprintf("%s:%d", ip, udpPort)
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

func getQuicSession(ip string, force bool) (quic.Session, error) {
	session, err := clientCache.Get(ip)
	if err != nil {
		if !force {
			return nil, err
		}
		session, err = clientConnect(ip)
		if err != nil {
			return nil, err
		}
		clientCache.Add(ip, session)
	} else {
		printDebug("Reusing session for ip: %s", ip)
	}
	return session, nil
}

// Handle proxy's quic requests to authoritative nameserver
func quicClientSend(ip string, msg []byte, session quic.Session, force bool) ([]byte, error) {
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		if !force {
			return nil, err
		}
		// try reconnecting first
		printDebug("Failed on first stream try ip: %s", ip)
		session, err = clientConnect(ip)
		if err != nil {
			return nil, err
		}
		clientCache.Add(ip, session)

		stream, err = session.OpenStreamSync(context.Background())
		if err != nil {
			printDebug("Failed on second stream try ip: %s", ip)
			return nil, err
		}
	}
	defer stream.Close()

	printDebug("Sending QUIC")
	printDebug("Client: Sending '%s'", string(msg))
	n, err := stream.Write(msg)
	if err != nil {
		return nil, err
	}
	printDebug("Sent proxy server %d bytes", n)

	buff := make([]byte, buffSize)
	n, err = readFromSession(stream, buff)
	if err != nil {
		return nil, err
	}

	return buff[0:n], nil
}
