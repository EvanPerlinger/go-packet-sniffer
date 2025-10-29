package parser

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func AnalyzePacket(packet gopacket.Packet) {
	fmt.Println("--- Packet Start ---")

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf(" [Link] MAC: %s -> %s\n", eth.SrcMAC, eth.DstMAC)
	}

	if netLayer := packet.NetworkLayer(); netLayer != nil {
		fmt.Printf(" [Net] IP: %s -> %s\n", netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst())
	}

	if tranptLayer := packet.TransportLayer(); tranptLayer != nil {
		fmt.Printf(" [Transport] Protocol: %s | Ports: %s -> %s\n", tranptLayer.TransportFlow().String(), tranptLayer.TransportFlow().Src(), tranptLayer.TransportFlow().Dst())
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		fmt.Printf(" [App] Data Length: %d bytes\n", len(appLayer.Payload()))
		fmt.Printf(" [App] Data (snippet): %s\n", appLayer.Payload()[:30])
	}

	fmt.Println("--- Packet End ---")
}
