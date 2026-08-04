package analyze

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/gopacket"
)

// Временный тест: печатает, что реально возвращает newPacketReader,
// чтобы понять причину нулевых счётчиков в TestDeepScanEthernetTraffic
// без ещё одного раунда угадывания через CI. Удалить после фикса.
func TestDebugPacketReader(t *testing.T) {
	f, err := os.Open("testdata/eth.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	reader, linkType, err := newPacketReader(f)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}
	fmt.Printf("DEBUG: linkType=%v rawLinkType=%d\n", linkType, int(linkType))

	count := 0
	var firstLen int
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadPacketData на пакете %d: %v", count, err)
		}
		if count == 0 {
			firstLen = len(data)
		}
		count++
	}
	fmt.Printf("DEBUG: прочитано пакетов=%d firstPacketLen=%d\n", count, firstLen)
	if count == 0 {
		t.Fatal("DEBUG: 0 пакетов прочитано")
	}

	f2, err := os.Open("testdata/eth.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	reader2, linkType2, err := newPacketReader(f2)
	if err != nil {
		t.Fatalf("newPacketReader (2): %v", err)
	}
	data, _, err := reader2.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData (2): %v", err)
	}
	pkt := gopacket.NewPacket(data, linkType2.LayerType(), gopacket.Default)
	fmt.Printf("DEBUG: baseLayerType=%v decodedLayers=%v errorLayer=%v\n",
		linkType2.LayerType(), pkt.Layers(), pkt.ErrorLayer())
}
