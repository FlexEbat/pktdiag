// Package analyze: DeepScan обнаруживает фрагментацию, SYN flood и
// ICMP-ошибки через построчный разбор пакетов gopacket. tshark считает
// эти метрики только по display-filter, gopacket даёт прямой доступ к
// полям IP/TCP/ICMP-заголовков.
//
// GitHub Actions собирает этот файл вместо локальной песочницы: сеть
// песочницы блокирует golang.org/x/*, от которого зависит gopacket
// (см. .github/workflows/ci.yml и раздел Known limitations в README).
package analyze

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// DeepScanResult хранит счётчики построчного разбора pcap через gopacket.
type DeepScanResult struct {
	TotalIPv4  int
	Fragmented int // IPv4 с MF=1 или fragment offset != 0
	SynOnly    int // TCP SYN без ACK (попытки установления соединения)
	SynAck     int // TCP SYN+ACK (успешный ответ на попытку)
	ICMPErrors int // ICMPv4 с кодом ошибки (не echo request/reply)
}

// icmpErrorTypes перечисляет типы ICMPv4, которые сигнализируют об
// ошибке. Echo request(8) и reply(0) исключены: это обычный ping.
var icmpErrorTypes = map[uint8]bool{
	3:  true, // Destination Unreachable
	4:  true, // Source Quench
	5:  true, // Redirect
	11: true, // Time Exceeded
	12: true, // Parameter Problem
}

// DeepScan читает pcap/pcapng файл через gopacket и считает пакеты,
// подходящие под фрагментацию/SYN-flood/ICMP-ошибки.
func DeepScan(pcapPath string) (DeepScanResult, error) {
	var res DeepScanResult

	f, err := os.Open(pcapPath)
	if err != nil {
		return res, fmt.Errorf("открытие %s: %w", pcapPath, err)
	}
	defer f.Close()

	reader, linkType, err := newPacketReader(f)
	if err != nil {
		return res, err
	}
	baseLayer := linkType.LayerType()

	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fmt.Errorf("чтение пакета: %w", err)
		}

		packet := gopacket.NewPacket(data, baseLayer, gopacket.NoCopy)

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, ok := ipLayer.(*layers.IPv4)
			if ok {
				res.TotalIPv4++
				if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
					res.Fragmented++
				}
			}
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if ok {
				switch {
				case tcp.SYN && tcp.ACK:
					res.SynAck++
				case tcp.SYN && !tcp.ACK:
					res.SynOnly++
				}
			}
		}

		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, ok := icmpLayer.(*layers.ICMPv4)
			if ok {
				if icmpErrorTypes[icmp.TypeCode.Type()] {
					res.ICMPErrors++
				}
			}
		}
	}

	return res, nil
}

// newPacketReader определяет формат файла (pcap классический или pcapng)
// по магическим байтам и возвращает подходящий gopacket-ридер вместе с
// его link-layer типом. tcpdump на интерфейсе "any" пишет Linux cooked
// capture (LINUX_SLL2), а не Ethernet, поэтому базовый слой для
// gopacket.NewPacket нельзя жёстко задавать: берём его из заголовка файла.
func newPacketReader(f *os.File) (packetDataReader, layers.LinkType, error) {
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return nil, 0, fmt.Errorf("чтение магических байт: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}

	// Формат pcapng начинается с блока 0x0A0D0D0A.
	isNg := (magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A)
	if isNg {
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, 0, fmt.Errorf("pcapng reader: %w", err)
		}
		iface, err := r.Interface(0)
		if err != nil {
			return nil, 0, fmt.Errorf("pcapng: интерфейс захвата: %w", err)
		}
		return r, iface.LinkType, nil
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, 0, fmt.Errorf("pcap reader: %w", err)
	}
	return r, r.LinkType(), nil
}

// packetDataReader объединяет pcapgo.Reader и pcapgo.NgReader: оба типа
// реализуют ReadPacketData, newPacketReader возвращает любой из них.
type packetDataReader interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
}
