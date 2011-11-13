package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
)

var (
	flagPort = flag.Int("port", 1080, "listening port")
)

func main() {
	flag.Parse()

	addr := &net.TCPAddr{IP: []byte{0, 0, 0, 0}, Port: *flagPort}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *flagPort, err)
	}

	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			log.Fatalf("Failed to accept new client connection: %v", err)
			e := err.(net.Error)
			if !e.Temporary() {
				os.Exit(1)
			}
		}
		go clientLoop(client)
	}
}

func clientLoop(client *net.TCPConn) {
	addr := client.RemoteAddr()
	defer client.Close()

	var versionMethod [2]byte
	_, err := io.ReadFull(client, versionMethod[:])
	if err != nil {
		log.Printf("%v: Failed to read the version and methods number: %v", addr, err)
		return
	}

	if versionMethod[0] != 0x05 {
		log.Printf("%v: Only implemented socks5 proxy currently: %X.", addr, versionMethod[0])
		return
	}

	nMethods := versionMethod[1]
	if nMethods == 0 {
		log.Printf("%v: Must provide one method at least.", addr)
		return
	}

	methods := make([]byte, nMethods)
	_, err = io.ReadFull(client, methods)
	if err != nil {
		log.Printf("%v: Failed to read the methods: %v", addr, err)
		return
	}

	hasMethod0 := false
	for i := 0; i < int(nMethods); i++ {
		if methods[i] == 0x00 {
			hasMethod0 = true
			break
		}
	}
	if !hasMethod0 {
		log.Printf("%v: Only implemented 'no authentication required' method currently.", addr)
		return
	}

	versionMethod[1] = 0x00
	nw, err := client.Write(versionMethod[:])
	if err != nil || nw != len(versionMethod) {
		log.Printf("%v: Failed to write version and method back to the client: %v", addr, err)
		return
	}

	var requestHeader [4]byte
	_, err = io.ReadFull(client, requestHeader[:])
	if err != nil {
		log.Printf("%v: Failed to read the request header: %v", addr, err)
		return
	}

	var reply [22]byte
	reply[0] = 0x05 // VER
	reply[2] = 0x00 // RSV
	if requestHeader[0] != 0x05 {
		log.Printf("%v: Version number in the request does not match the previous one: %X", addr, requestHeader[0])
		return
	}
	if requestHeader[1] != 0x01 {
		log.Printf("%v: Only implemented CONNECT command currently.", addr)
		reply[1] = 0x07
		client.Write(reply[:4])
		return
	}
	if requestHeader[2] != 0x00 {
		log.Printf("%v: RESERVED field must be 0.", addr)
		return
	}

	remoteAddress := new(net.TCPAddr)
	switch requestHeader[3] {
	case 0x01, 0x04:
		{
			ipLen := 4 * requestHeader[3]
			buf := make([]byte, ipLen+2)
			_, err = io.ReadFull(client, buf)
			if err != nil {
				log.Printf("%v: Failed to read requested address: %v", addr, err)
				return
			}
			remoteAddress.IP = buf[:ipLen]
			remoteAddress.Port = int(buf[ipLen])<<8 + int(buf[ipLen+1])
			reply[3] = requestHeader[3]
		}
	case 0x03:
		{
			var hostLen [1]byte
			_, err = io.ReadFull(client, hostLen[:])
			if err != nil {
				log.Printf("%v: Failed to read requested host len: %v", addr, err)
				return
			}
			host := make([]byte, hostLen[0])
			_, err = io.ReadFull(client, host)
			if err != nil {
				log.Printf("%v: Failed to read requested host name: %v", addr, err)
				return
			}
			ips, err := net.LookupIP(string(host))
			if err != nil {
				log.Printf("%v: Failed to resolve requested host: %v", addr, err)
				return
			}
			if len(ips) == 0 {
				log.Printf("%v: There is no IP address corresponding to host '%s'.", addr, host)
				return
			}
			remoteAddress.IP = ips[0]
			reply[3] = len(ips[0]) / 4
			var port [2]byte
			_, err = io.ReadFull(client, port[:])
			if err != nil {
				log.Printf("%v: Failed to read requested port: %v", addr, err)
				return
			}
			remoteAddress.Port = int(port[0])<<8 + int(port[1])
		}
	default:
		log.Printf("%v: unknown address type: %X", addr, requestHeader[3])
		reply[1] = 0x08
		client.Write(reply[:4])
		return
	}
	log.Printf("%v: Requested address: %v", addr, remoteAddress)

	remote, err := net.DialTCP("tcp", nil, remoteAddress)
	if err != nil {
		log.Printf("%v: Failed to connect to the requested address: %v", addr, err)
		reply[1] = 0x05
		client.Write(reply[:6])
		return
	}
	defer remote.Close()

	reply[1] = 0x00
	ipEnd := 4 + 4*reply[3]
	copy(reply[4:ipEnd], remoteAddress.IP)
	reply[ipEnd] = byte(remoteAddress.Port >> 8)
	reply[ipEnd+1] = byte(remoteAddress.Port % 256)
	_, err = client.Write(reply[:ipEnd+2])
	if err != nil {
		log.Printf("%v: Failed to write reply: %v", addr, err)
		return
	}

	stopChan := make(chan bool)
	go readClientLoop(client, remote, stopChan)
	go readRemoteLoop(client, remote, stopChan)
	_ = <-stopChan
	_ = <-stopChan
}

func readClientLoop(client, remote *net.TCPConn, stopChan chan<- bool) {
	defer func() {
		stopChan <- true
	}()
	addr := client.RemoteAddr()

	for {
		var buf [4096]byte
		nr, err := client.Read(buf[:])
		if err != nil && err != os.EOF {
			log.Printf("%v: Failed to read from the client: %v", addr, err)
			return
		}

		start := 0
		for start < nr {
			nw, err := remote.Write(buf[start:nr])
			if err != nil && err != os.EOF {
				log.Printf("%v: Failed to write to the remote: %v", addr, err)
				return
			}
			start += nw
		}
	}
}

func readRemoteLoop(client, remote *net.TCPConn, stopChan chan<- bool) {
	defer func() {
		stopChan <- true
	}()
	addr := client.RemoteAddr()

	for {
		var buf [4096]byte
		nr, err := remote.Read(buf[:])
		if err != nil && err != os.EOF {
			log.Printf("%v: Failed to read from the remote: %v", addr, err)
			return
		}

		start := 0
		for start < nr {
			nw, err := client.Write(buf[start:nr])
			if err != nil && err != os.EOF {
				log.Printf("%v: Failed to write to the client: %v", addr, err)
				return
			}
			start += nw
		}
	}
}
