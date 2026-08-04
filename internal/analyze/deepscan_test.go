package analyze

import "testing"

// testdata/mixed.pcapng захвачен на интерфейсе any (Linux cooked v2,
// не Ethernet, что и стало причиной бага с жёстко заданным LinkType)
// и содержит: 2 фрагментированных ping (по 3 фрагмента каждый), один
// ICMP Destination Unreachable от закрытого UDP-порта на loopback,
// один завершённый TCP handshake (SYN, SYN+ACK, ACK). Точные счётчики
// проверены через tshark отдельно от gopacket, до написания теста.
func TestDeepScanMixedTraffic(t *testing.T) {
	res, err := DeepScan("testdata/mixed.pcapng")
	if err != nil {
		t.Fatalf("DeepScan вернул ошибку: %v", err)
	}

	cases := []struct {
		name string
		got  int
		want int
	}{
		{"TotalIPv4", res.TotalIPv4, 34},
		{"Fragmented", res.Fragmented, 6},
		{"SynOnly", res.SynOnly, 1},
		{"SynAck", res.SynAck, 1},
		{"ICMPErrors", res.ICMPErrors, 1},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, ожидалось %d", c.name, c.got, c.want)
		}
	}
}
