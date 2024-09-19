package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var m = make(map[string]bool)
var a = []string{}

// Add IP to the list only if not already added
func add(s string) {
	if m[s] {
		return // Already in the map
	}
	a = append(a, s)
	m[s] = true
	log.Printf("Found IP: %s", s)
}

func main() {
	// List all available network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Error getting interfaces: %s", err)
	}

	fmt.Println("Available network interfaces:")
	for idx, iface := range interfaces {
		fmt.Printf("[%d] %s (%s)\n", idx, iface.Name, iface.HardwareAddr.String())
	}

	// Ask user to select an interface
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Select the interface number you want to scan (or press Enter for custom IP range): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var ipRange string
	if input == "" {
		// Custom IP range
		fmt.Print("Enter custom IP range (e.g., 192.168.1.1-192.168.1.254): ")
		ipRange, _ = reader.ReadString('\n')
		ipRange = strings.TrimSpace(ipRange)
	} else {
		// Scan IPs on the selected interface's subnet
		interfaceIndex, _ := strconv.Atoi(input)
		selectedInterface := interfaces[interfaceIndex]
		addrs, err := selectedInterface.Addrs()
		if err != nil {
			log.Fatalf("Error getting addresses: %s", err)
		}

		// Look for the first valid IPv4 address and parse it
		for _, addr := range addrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil {
				ipRange = getIPRange(ipNet)
				fmt.Printf("Scanning range: %s\n", ipRange)
				break
			}
		}

		if ipRange == "" {
			log.Fatalf("No valid IPv4 address found for interface %s", selectedInterface.Name)
		}
	}

	// Parse IP range
	startIP, endIP := parseIPRange(ipRange)

	log.Printf("Starting Scan...")

	// Open ICMP connection
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Error creating connection: %s", err)
	}
	defer c.Close()

	var wg sync.WaitGroup

	for ip := ipToInt(startIP); ip <= ipToInt(endIP); ip++ {
		wg.Add(1)
		go func(ip int) {
			defer wg.Done()
			targetIP := intToIP(ip)
			if err := ping(c, targetIP, ip); err != nil {
				log.Printf("Error pinging %s: %s", targetIP, err)
			}
		}(ip)
	}

	wg.Wait()

	// Sort IPs correctly
	sort.Slice(a, func(i, j int) bool {
		return ipToInt(a[i]) < ipToInt(a[j])
	})

	log.Printf("Unique IPs: %v", len(a))
	log.Println("List of IPs in order:")
	for _, ip := range a {
		log.Println(ip)
	}
}

// Ping function remains unchanged
func ping(c *icmp.PacketConn, targetIP string, seq int) error {
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   (os.Getpid() & 0xffff) + seq,
			Seq:  seq,
			Data: []byte("T"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}

	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)}); err != nil {
		return err
	}

	rb := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(5 * time.Second)) // Set a read timeout of 5 seconds

	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// log.Printf("Timeout waiting for response from %s", targetIP)
		} else {
			return err
		}
		return nil
	}

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		return err
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		// if echoReply, ok := rm.Body.(*icmp.Echo); ok {
		// log.Printf("Received valid response from %v, ID: %v", peer, echoReply.ID)
		add(peer.String())
		// }
	default:
	}

	return nil
}

// ipToInt converts an IP address string to an integer.
func ipToInt(ipStr string) int {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return int(ip[0])<<24 + int(ip[1])<<16 + int(ip[2])<<8 + int(ip[3])
}

// intToIP converts an integer back to an IP address.
func intToIP(ipInt int) string {
	return fmt.Sprintf("%d.%d.%d.%d", (ipInt>>24)&0xFF, (ipInt>>16)&0xFF, (ipInt>>8)&0xFF, ipInt&0xFF)
}

// parseIPRange takes a string like "192.168.1.1-192.168.1.254" and returns the start and end IPs.
func parseIPRange(rangeStr string) (startIP, endIP string) {
	ips := strings.Split(rangeStr, "-")
	if len(ips) == 2 {
		return ips[0], ips[1]
	}
	return "0.0.0.0", "0.0.0.0" // Invalid range
}

// getIPRange extracts the IP range from a CIDR address.
func getIPRange(ipNet *net.IPNet) string {
	ip := ipNet.IP.To4()
	if ip == nil {
		return "Invalid"
	}

	startIP := ip.String()
	endIP := lastIPInRange(ipNet).String()

	return fmt.Sprintf("%s-%s", startIP, endIP)
}

// lastIPInRange calculates the last IP address in a network range.
func lastIPInRange(ipNet *net.IPNet) net.IP {
	ip := ipNet.IP.To4()
	last := make(net.IP, len(ip))
	copy(last, ip)
	for i := 0; i < len(last); i++ {
		last[i] |= ^ipNet.Mask[i]
	}
	return last
}
