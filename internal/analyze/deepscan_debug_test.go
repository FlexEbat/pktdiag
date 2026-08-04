package analyze

import (
	"fmt"
	"io"
	"os"
	"testing"
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
}
