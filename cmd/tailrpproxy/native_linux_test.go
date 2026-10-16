//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/eseiker/tailrpproxy/internal/rpproxy"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn"
	"tailscale.com/types/opt"
)

// Only the packet-loop methods are implemented; no real TUN or tailnet is used.
type packetTestDevice struct {
	tun.Device
	batchSize int
	read      func([]byte, []tun.ReadPacket) (int, error)
	write     func([][]byte, int) (int, error)
}

func (device *packetTestDevice) BatchSize() int { return device.batchSize }
func (device *packetTestDevice) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	return device.read(slab, packets)
}
func (device *packetTestDevice) Write(packets [][]byte, offset int) (int, error) {
	return device.write(packets, offset)
}

func TestServePacketReflectorReadsPacketOffsetsAndBatchCounts(t *testing.T) {
	reflector, err := rpproxy.NewPacketReflector(netip.MustParsePrefix("10.7.0.1/32"), true)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 20+len("rppairing"))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{100, 100, 4, 3})
	copy(packet[16:20], []byte{10, 7, 0, 1})
	copy(packet[20:], "rppairing")
	want := bytes.Clone(packet)
	copy(want[12:16], packet[16:20])
	copy(want[16:20], packet[12:16])

	reads, writes := 0, 0
	device := &packetTestDevice{batchSize: 3}
	device.read = func(slab []byte, packets []tun.ReadPacket) (int, error) {
		reads++
		if len(packets) < device.batchSize || len(slab) < device.batchSize*(65535+tun.ReadPacketSpacing)+tun.ReadPacketSpacing {
			t.Fatal("read buffers cannot hold full packets with required spacing")
		}
		if reads == 3 {
			return 0, io.EOF
		}
		count := 3
		if reads == 2 {
			count = 1 // Entries beyond count retain stale metadata from the first read.
		}
		offset := tun.ReadPacketSpacing
		for index := range count {
			copy(slab[offset:], packet)
			packets[index] = tun.ReadPacket{Offset: offset, Size: len(packet)}
			if index == 1 {
				slab[offset+19] = 2 // A different destination must be discarded.
			}
			offset += len(packet) + tun.ReadPacketSpacing
		}
		return count, nil
	}
	device.write = func(packets [][]byte, offset int) (int, error) {
		writes++
		wantCount := 2
		if writes == 2 {
			wantCount = 1
		}
		if offset < tun.ReadPacketSpacing || len(packets) != wantCount {
			t.Fatalf("write offset=%d count=%d, want reserved headroom and %d packets", offset, len(packets), wantCount)
		}
		for _, packet := range packets {
			if !bytes.Equal(packet[offset:], want) {
				t.Fatalf("reflected packet = %x, want %x", packet[offset:], want)
			}
		}
		return len(packets), nil
	}
	if err := servePacketReflector(device, reflector); !errors.Is(err, io.EOF) {
		t.Fatalf("serve error = %v, want EOF", err)
	}
	snapshot := reflector.Metrics().Snapshot()
	if writes != 2 || snapshot.PacketsReflected != 3 || snapshot.Rejected != 1 {
		t.Fatalf("writes=%d metrics=%+v", writes, snapshot)
	}
}

func TestServePacketReflectorReadAndWriteErrors(t *testing.T) {
	writeErr := errors.New("write failed")
	for _, test := range []struct {
		name      string
		readCount int
		writeErr  error
		wantErr   error
	}{
		{name: "read error", wantErr: io.EOF},
		{name: "packets returned with read error", readCount: 1, wantErr: io.EOF},
		{name: "write error", readCount: 1, writeErr: writeErr, wantErr: writeErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			reflector, err := rpproxy.NewPacketReflector(netip.MustParsePrefix("10.7.0.1/32"), true)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			device := &packetTestDevice{ // Zero BatchSize must still allocate one entry.
				read: func(slab []byte, packets []tun.ReadPacket) (int, error) {
					if len(packets) != 1 {
						t.Fatalf("packet entries = %d, want 1", len(packets))
					}
					offset := tun.ReadPacketSpacing
					packet := slab[offset : offset+20]
					packet[0] = 0x45
					binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
					copy(packet[12:16], []byte{100, 64, 0, 2})
					copy(packet[16:20], []byte{10, 7, 0, 1})
					packets[0] = tun.ReadPacket{Offset: offset, Size: len(packet)}
					return test.readCount, io.EOF
				},
				write: func(packets [][]byte, offset int) (int, error) {
					writes++
					return len(packets), test.writeErr
				},
			}
			if err := servePacketReflector(device, reflector); !errors.Is(err, test.wantErr) {
				t.Fatalf("serve error = %v, want %v", err, test.wantErr)
			}
			if writes != test.readCount {
				t.Fatalf("writes = %d, want %d", writes, test.readCount)
			}
		})
	}
}

func TestNativeRoutePrefsConfiguresDedicatedRoute(t *testing.T) {
	configured, err := nativeRoutePrefs(&ipn.Prefs{}, netip.MustParsePrefix("10.7.0.1/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(configured.AdvertiseRoutes) != 1 || configured.AdvertiseRoutes[0].String() != "10.7.0.1/32" {
		t.Fatalf("routes = %v", configured.AdvertiseRoutes)
	}
	if !configured.NoSNAT || configured.NoStatefulFiltering != opt.True {
		t.Fatalf("unsafe subnet preferences: %+v", configured.Prefs)
	}
}

func TestNativeTUNLocalAddress(t *testing.T) {
	address, err := nativeTUNLocalAddress(netip.MustParsePrefix("10.7.0.1/32"))
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "10.7.0.0" {
		t.Fatalf("local address = %s, want 10.7.0.0", got)
	}
	if _, err := nativeTUNLocalAddress(netip.MustParsePrefix("0.0.0.0/32")); err == nil {
		t.Fatal("zero route did not return an error")
	}
}

func TestNativeRoutePrefsPreservesCompatibleRoutes(t *testing.T) {
	configured, err := nativeRoutePrefs(&ipn.Prefs{
		AdvertiseRoutes:     []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		NoSNAT:              true,
		NoStatefulFiltering: opt.True,
	}, netip.MustParsePrefix("10.7.0.1/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(configured.AdvertiseRoutes) != 2 {
		t.Fatalf("routes = %v, want existing and synthetic routes", configured.AdvertiseRoutes)
	}
}

func TestNativeRoutePrefsRejectsGlobalPolicyChanges(t *testing.T) {
	route := netip.MustParsePrefix("10.7.0.1/32")
	otherRoute := netip.MustParsePrefix("192.0.2.0/24")
	for _, prefs := range []*ipn.Prefs{
		{AdvertiseRoutes: []netip.Prefix{otherRoute}},
		{AdvertiseRoutes: []netip.Prefix{otherRoute}, NoSNAT: true, NoStatefulFiltering: opt.False},
	} {
		if _, err := nativeRoutePrefs(prefs, route); err == nil {
			t.Fatalf("preferences %+v did not return an error", prefs)
		}
	}
}
