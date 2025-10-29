package main

import (
	"flag"
	"fmt"
	"go-packet-sniffer/internal/parser"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	device         string
	snapshotLen    int32         = 1024
	promiscuous    bool          = false
	timeout        time.Duration = 30 * time.Second
	interfaceIndex int
)

func init() {
	flag.IntVar(&interfaceIndex, "i", -1, "Network interface to sniff on (e.g., eth0, en0)")
}

func main() {

	flag.Parse()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if interfaceIndex >= 0 && interfaceIndex < len(devices) {
		device = devices[interfaceIndex].Name
	}

	if device == "" {
		fmt.Println("Please specify a network interface using the -i flag.")
		fmt.Println("Available interfaces: ")
		for i, device := range devices {
			fmt.Printf("[%d] - [%s] \n", i, device.Name)
		}
		return
	}

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error opening device %s. Try running with sudo: %v", device, err)
	}
	defer handle.Close()

	filter := "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Error setting BPF filer: %v", err)
	}

	fmt.Printf("Sniffing on device %s, filter: %s\n", device, filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		parser.AnalyzePacket(packet)
	}
}
