package analyze

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// Временный тест: смотрит рядовые байты первых пакетов mixed.pcapng,
// чтобы проверить структуру заголовка SLL2, которую предполагает
// startLayer. Удалить после фикса.
func TestDebugMixedPackets(t *testing.T) {
	f, err := os.Open("testdata/mixed.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	reader, linkType, err := newPacketReader(f)
	if err != nil {
		t.Fatalf("newPacketReader: %v", err)
	}
	fmt.Printf("DEBUG mixed: linkType=%v rawLinkType=%d\n", linkType, int(linkType))

	for i := 0; i < 5; i++ {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			t.Fatalf("ReadPacketData на пакете %d: %v", i, err)
		}
		n := 24
		if len(data) < n {
			n = len(data)
		}
		fmt.Printf("DEBUG mixed: packet[%d] len=%d first24=%s\n", i, len(data), hex.EncodeToString(data[:n]))
	}
}
