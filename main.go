// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// synscan-based scanner

//
// Since this is just an example program, it aims for simplicity over
// performance.  It doesn't handle sending packets very quickly, it scans IPs
// serially instead of in parallel, and uses gopacket.Packet instead of
// gopacket.DecodingLayerParser for packet processing.  We also make use of very
// simple timeout logic with time.Since.
//
// Making it blazingly fast is left as an exercise to the reader.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	insecureRand "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

var defaultMSS = []byte("\x00\x45")

var flagIgnoreMSS = flag.Bool("ignore-mss", false, "ignore mss (useful for MSS-overriding NATs)")
var flagSrcPort = flag.Int("port", 0, "source port (default: random)")
var flagDelay = flag.Duration("delay", 8*time.Millisecond, "delay between probes")
var portsToScan = []layers.TCPPort{443, 80, 21, 23, 22, 25, 123, 465, 587, 161, 53, 554, 9100, 7627, 5060}

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func newScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	//log.Printf("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	// Open the handle for reading/writing.
	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	handle, err := pcap.OpenLive(iface.Name, 4096, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFFilter(fmt.Sprintf("arp or ip src host %s", ip))
	if err != nil {
		return nil, err
	}
	s.handle = handle
	return s, nil
}

// close cleans up the handle.
func (s *scanner) close() {
	s.handle.Close()
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (s *scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(arpDst) {
				return arp.SourceHwAddress, nil
			}
		}
	}
}

// scan scans the dst IP address of this scanner.
func (s *scanner) scan() (bool, error) {
	hwAddr, err := s.getHwAddr()
	if err != nil {
		return false, err
	}
	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       hwAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	srcPort := *flagSrcPort
	if srcPort == 0 {
		srcPort = 10000 + insecureRand.Intn(50000)
	}
	sendTCP := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: 0,
		SYN:     true,
		Window:  123,
		Options: []layers.TCPOption{
			{layers.TCPOptionKindMSS, 4, defaultMSS},
			{layers.TCPOptionKindSACKPermitted, 2, nil},
			{layers.TCPOptionKindNop, 1, nil},
			{layers.TCPOptionKindNop, 1, nil},
			{layers.TCPOptionKindTimestamps, 10, make([]byte, 8)},
			{layers.TCPOptionKindNop, 1, nil},
			{layers.TCPOptionKindNop, 1, nil},
			{layers.TCPOptionKindWindowScale, 3, []byte{1}},
			{layers.TCPOptionKindNop, 1, nil},
		},
	}

	if err := sendTCP.SetNetworkLayerForChecksum(&ip4); err != nil {
		return false, fmt.Errorf("failed to setup checksums: %w", err)
	}

	doneCh := make(chan struct{}, 1)
	defer close(doneCh)

	go func() {
		for _, port := range portsToScan {
			select {
			case <-doneCh:
				return
			default:
			}
			sendTCP.DstPort = port
			if err := s.send(&eth, &ip4, &sendTCP); err != nil {
				log.Printf("error sending to port %v: %v", sendTCP.DstPort, err)
			}
		}
	}()

	// XXX remove?
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)
	start := time.Now()

	for {
		if time.Since(start) > 1*time.Second {
			return false, nil
		}

		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}

		// Parse the packet.  We'd use DecodingLayerParser here if we
		// wanted to be really fast.
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		matched, reason, err := match(ipFlow, packet)
		if err != nil {
			//XXX debug
			//log.Printf("matcher failed: %w", err)
			continue
		}
		if matched {
			return true, fmt.Errorf("matched: %s", reason)
		}
	}
}

func match(ipFlow gopacket.Flow, packet gopacket.Packet) (bool, string, error) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return false, "", fmt.Errorf("no-netlayer: %+v", packet.LinkLayer().LayerContents())
	}
	if netLayer.NetworkFlow() != ipFlow {
		return false, "", fmt.Errorf("unknown flow: %+v", netLayer.NetworkFlow())
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false, "", fmt.Errorf("no TCP layer: %+v", netLayer.LayerContents())
	}
	recvTCP, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return false, "", fmt.Errorf("not TCP: %+v", netLayer.LayerContents())
	}
	if !(recvTCP.SYN && recvTCP.ACK) {
		return false, "", fmt.Errorf("wrong TCP flags")
	}

	var matchedWS, matchedMSS, matchedTS bool
	matchedMSS = *flagIgnoreMSS
	for _, opt := range recvTCP.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindWindowScale:
			if bytes.Compare(opt.OptionData, []byte{0}) == 0 {
				matchedWS = true
			}
		case layers.TCPOptionKindMSS:
			if bytes.Compare(opt.OptionData, defaultMSS) == 0 {
				matchedMSS = true
			}
		case layers.TCPOptionKindTimestamps:
			matchedTS = true
		}
	}
	if matchedWS && matchedMSS && matchedTS {
		return true, fmt.Sprintf("TRECK: port %v open", recvTCP.SrcPort), nil
	}
	return false, fmt.Sprintf("open port %v open", recvTCP.SrcPort), nil
}

// send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func main() {
	flag.Parse()

	nArgs := len(flag.Args())
	if nArgs == 0 {
		flag.Usage()
		os.Exit(64)
	}

	ips := make([]net.IP, 0)
	for _, arg := range flag.Args() {
		_, ipnet, err := net.ParseCIDR(arg)
		if err != nil {
			panic(fmt.Errorf("non-cidr target: %q", arg))
		}
		ips = append(ips, expandSubnet(ipnet)...)
	}
	insecureRand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })

	log.Printf("Scanning %d IPs from %d subnets", len(ips), nArgs)

	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}

	limiter := time.NewTicker(*flagDelay)
	defer limiter.Stop()

	wg := sync.WaitGroup{}

	for _, ip := range ips {
		ip := ip

		<-limiter.C
		wg.Add(1)
		go func() {
			defer wg.Done()

			s, err := newScanner(ip, router)
			if err != nil {
				log.Printf("unable to create scanner for %v: %v", ip, err)
				return
			}
			defer s.close()

			if matched, err := s.scan(); err != nil {
				if matched {
					log.Printf("treck stack found: %s: %s", ip, err)
				} else {
					log.Printf("unable to scan %v: %v", ip, err)
				}
			} else {
				log.Printf("non treck stack: %s", ip)
			}
		}()
	}
	wg.Wait()
}

func expandSubnet(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32(n.IP)
	mask := binary.BigEndian.Uint32(n.Mask)
	num &= mask
	for {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, buf[:])

		if mask == 0xffffffff {
			return
		}

		mask++
		num++
	}
}
