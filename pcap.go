package main

import (
	"encoding/hex"
	"fmt"
	"github.com/florianl/go-nflog/v2"
	"github.com/go-logfmt/logfmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/common/model"
	"time"
)

type Pcap struct {
	ethernet layers.Ethernet
	ip4      layers.IPv4
	tcp      layers.TCP
	udp      layers.UDP
	ntp      layers.NTP
	icmpv4   layers.ICMPv4

	dhcpv4 layers.DHCPv4

	decoder         *gopacket.DecodingLayerParser
	foundLayerTypes []gopacket.LayerType
	input           chan *nflog.Attribute
	pusher          *LokiPublisher
}

func NewPcap(bufferPackets int, pusher *LokiPublisher) *Pcap {
	p := Pcap{
		pusher: pusher,
		input:  make(chan *nflog.Attribute, bufferPackets),
	}

	protocols := []gopacket.DecodingLayer{
		&p.ip4,
		&p.icmpv4,
		&p.tcp,
		&p.udp,
		&p.dhcpv4,
	}

	p.decoder = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, protocols...)
	p.foundLayerTypes = make([]gopacket.LayerType, 0, len(protocols))

	return &p
}

func (p *Pcap) Run() {
	var err error
	for {
		msg := <-p.input

		labels := model.LabelSet{
			"job":    model.LabelValue("nflog"),
			"prefix": model.LabelValue(*msg.Prefix),
		}
		var values []interface{}

		payload := msg.Payload

		err = p.decoder.DecodeLayers(*payload, &p.foundLayerTypes)

		//hwheader := msg.HwHeader
		//fmt.Printf("HWHEADER (%d,%d): [ ", *msg.HwLen, *msg.HwProtocol)
		//for j := 0; j < len(*hwheader); j = j + 1 {
		//	fmt.Printf("%02X ", (*hwheader)[j])
		//}
		//fmt.Printf("]\n")

		//if msg.Ct != nil {
		//	fmt.Printf("has Ct %v\n", *msg.Ct)
		//}
		//
		//if msg.CtInfo != nil {
		//	ctinfo := *msg.CtInfo
		//	fmt.Printf("has Ct %v\n", ctinfo)
		//}

		hwheader := msg.HwHeader
		if hwheader != nil && len(*hwheader) == 14 {
			// This looks like an ethernet header.  There are 6 bytes of
			// destination address, followed by 6 bytes of source address,
			// followed by the protocol identifier.

			dst := (*hwheader)[0:5]
			dstStr := hex.EncodeToString(dst)
			src := (*hwheader)[6:11]
			srcStr := hex.EncodeToString(src)

			labels["dstaddr"] = model.LabelValue(dstStr)
			labels["srcaddr"] = model.LabelValue(srcStr)

		}

		if err == nil {
			for _, layerType := range p.foundLayerTypes {
				switch layerType {

				case layers.LayerTypeIPv4:

					values = append(values, "src", p.ip4.SrcIP.String(),
						"dst", p.ip4.DstIP.String())
				case layers.LayerTypeUDP:
					labels["proto"] = model.LabelValue("UDP")
					values = append(values,
						"sport", uint16(p.udp.SrcPort),
						"dport", uint16(p.udp.DstPort))
					srcPortName, ok := layers.UDPPortNames[p.udp.SrcPort]
					if ok {
						values = append(values, "sportname", srcPortName)
					}
					dstPortName, ok := layers.UDPPortNames[p.udp.DstPort]
					if ok {
						values = append(values, "dportname", dstPortName)
					}

				case layers.LayerTypeTCP:
					labels["proto"] = model.LabelValue("TCP")
					values = append(values,
						"sport", uint16(p.tcp.SrcPort),
						"dport", uint16(p.tcp.DstPort))

					srcPortName, ok := layers.TCPPortNames[p.tcp.SrcPort]
					if ok {
						values = append(values, "sportname", srcPortName)
					}
					dstPortName, ok := layers.TCPPortNames[p.tcp.DstPort]
					if ok {
						values = append(values, "dportname", dstPortName)
					}

				case layers.LayerTypeICMPv4:
					labels["proto"] = model.LabelValue("TCP")
					values = append(values,
						"code", uint16(p.icmpv4.TypeCode),
						"subtype", int16(p.icmpv4.Id),
						"type", p.icmpv4.TypeCode.String(),
						"seq", p.icmpv4.Seq)

				case layers.LayerTypeDHCPv4:
					labels["proto"] = model.LabelValue("DHCP")
					values = append(values,
						"operation", p.dhcpv4.Operation.String(),
						"client", p.dhcpv4.ClientIP.String())

				}

			}

			logbytes, err := logfmt.MarshalKeyvals(values...)
			if err == nil {
				p.pusher.input <- &LokiMessage{
					Labels:    labels,
					Timestamp: time.Time{},
					Message:   string(logbytes),
				}
			}

		} else {
			fmt.Errorf("decoder", err.Error())
		}
	}

}
