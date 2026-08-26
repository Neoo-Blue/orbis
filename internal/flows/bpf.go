//go:build linux

package flows

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// buildFilter assembles the kernel-side prefilter. This is the single most
// important performance decision in the capture path: without it every byte
// of every 4K stream is copied to userspace. With it, the kernel hands us
// only the packets that can actually teach us something:
//
//   - ARP, so we can bind MAC addresses to IPs
//   - TCP SYN / FIN / RST, which delimit flows
//   - TCP segments whose first payload byte is 0x16 (a TLS handshake record),
//     which is where the SNI lives
//   - TCP segments starting with an ASCII uppercase letter, catching cleartext
//     HTTP request lines (GET/POST/HEAD/...)
//   - UDP on 53 (DNS), 67/68 (DHCP), 443 (QUIC), 80, 123 (NTP), 5353 (mDNS)
//
// A bulk download therefore costs three or four delivered packets total
// instead of hundreds of thousands.
type asm struct {
	ins    []bpf.Instruction
	labels map[string]int
	fixups []fixup
}

type fixup struct {
	idx        int
	trueLabel  string
	falseLabel string
	jumpLabel  string
}

func newASM() *asm {
	return &asm{labels: map[string]int{}}
}

func (a *asm) emit(i bpf.Instruction) { a.ins = append(a.ins, i) }

func (a *asm) label(name string) { a.labels[name] = len(a.ins) }

// jeq emits a conditional jump to a label when equal, falling through
// otherwise. Offsets are patched once every label position is known.
func (a *asm) jeq(val uint32, trueLabel string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ins), trueLabel: trueLabel})
	a.emit(bpf.JumpIf{Cond: bpf.JumpEqual, Val: val})
}

func (a *asm) jset(val uint32, trueLabel string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ins), trueLabel: trueLabel})
	a.emit(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: val})
}

func (a *asm) jge(val uint32, trueLabel string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ins), trueLabel: trueLabel})
	a.emit(bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: val})
}

func (a *asm) jmp(target string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ins), jumpLabel: target})
	a.emit(bpf.Jump{})
}

func (a *asm) assemble() ([]bpf.RawInstruction, error) {
	for _, f := range a.fixups {
		// cBPF jump offsets count instructions *after* the jump itself, and
		// the 8-bit field caps a forward jump at 255.
		resolve := func(name string) (uint8, error) {
			pos, ok := a.labels[name]
			if !ok {
				return 0, fmt.Errorf("bpf: undefined label %q", name)
			}
			delta := pos - f.idx - 1
			if delta < 0 || delta > 255 {
				return 0, fmt.Errorf("bpf: jump to %q out of range (%d)", name, delta)
			}
			return uint8(delta), nil
		}
		switch ins := a.ins[f.idx].(type) {
		case bpf.JumpIf:
			skip, err := resolve(f.trueLabel)
			if err != nil {
				return nil, err
			}
			ins.SkipTrue = skip
			a.ins[f.idx] = ins
		case bpf.Jump:
			pos, ok := a.labels[f.jumpLabel]
			if !ok {
				return nil, fmt.Errorf("bpf: undefined label %q", f.jumpLabel)
			}
			delta := pos - f.idx - 1
			if delta < 0 {
				return nil, fmt.Errorf("bpf: backward jump to %q unsupported", f.jumpLabel)
			}
			ins.Skip = uint32(delta)
			a.ins[f.idx] = ins
		}
	}
	return bpf.Assemble(a.ins)
}

const (
	ethTypeOff = 12
	ethHdrLen  = 14

	etherARP  = 0x0806
	etherIPv4 = 0x0800
	etherIPv6 = 0x86dd

	protoTCP  = 6
	protoUDP  = 17
	protoICMP = 1
)

func buildFilter(snapLen int) ([]bpf.RawInstruction, error) {
	a := newASM()

	// A = ethertype
	a.emit(bpf.LoadAbsolute{Off: ethTypeOff, Size: 2})
	a.jeq(etherARP, "accept")
	a.jeq(etherIPv4, "ipv4")
	a.jeq(etherIPv6, "ipv6")
	a.jmp("drop")

	// ---- IPv4 ----
	a.label("ipv4")
	// Fragmented packets have no usable L4 header past the first fragment.
	a.emit(bpf.LoadAbsolute{Off: ethHdrLen + 6, Size: 2})
	a.jset(0x1fff, "drop")
	a.emit(bpf.LoadAbsolute{Off: ethHdrLen + 9, Size: 1}) // protocol
	a.jeq(protoTCP, "v4tcp")
	a.jeq(protoUDP, "v4udp")
	a.jeq(protoICMP, "accept")
	a.jmp("drop")

	a.label("v4udp")
	a.emit(bpf.LoadMemShift{Off: ethHdrLen}) // X = 4*(IHL)
	a.emit(bpf.LoadIndirect{Off: ethHdrLen, Size: 2})
	a.jmp("udpports")

	a.label("v4tcp")
	a.emit(bpf.LoadMemShift{Off: ethHdrLen})
	// TCP flags live at offset 13 of the TCP header.
	a.emit(bpf.LoadIndirect{Off: ethHdrLen + 13, Size: 1})
	a.jset(0x07, "accept") // FIN | SYN | RST
	// Compute payload offset: X = ip_hlen + tcp_hlen, then read first byte.
	a.emit(bpf.LoadIndirect{Off: ethHdrLen + 12, Size: 1})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2})
	a.emit(bpf.ALUOpX{Op: bpf.ALUOpAdd}) // A = tcp_hlen + ip_hlen
	a.emit(bpf.TAX{})                    // X = payload offset
	a.emit(bpf.LoadIndirect{Off: ethHdrLen, Size: 1})
	a.jeq(0x16, "accept") // TLS handshake record
	// Cleartext HTTP request lines start with an uppercase ASCII letter.
	a.jge(0x41, "maybe_http")
	a.jmp("drop")

	a.label("maybe_http")
	a.jge(0x5b, "drop") // past 'Z' => not a method token
	a.jmp("accept")

	// ---- IPv6 ----
	// Extension headers make the L4 offset variable; rather than walk the
	// chain in cBPF, accept the fixed-header cases and let userspace parse.
	a.label("ipv6")
	a.emit(bpf.LoadAbsolute{Off: ethHdrLen + 6, Size: 1}) // next header
	a.jeq(protoTCP, "v6tcp")
	a.jeq(protoUDP, "v6udp")
	a.jeq(58, "accept") // ICMPv6 (neighbour discovery)
	a.jmp("drop")

	a.label("v6udp")
	a.emit(bpf.LoadAbsolute{Off: ethHdrLen + 40, Size: 2}) // src port
	a.jmp("udpports")

	a.label("v6tcp")
	a.emit(bpf.LoadAbsolute{Off: ethHdrLen + 40 + 13, Size: 1})
	a.jset(0x07, "accept")
	a.emit(bpf.LoadAbsolute{Off: ethHdrLen + 40 + 12, Size: 1})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: ethHdrLen + 40})
	a.emit(bpf.TAX{})
	a.emit(bpf.LoadIndirect{Off: 0, Size: 1})
	a.jeq(0x16, "accept")
	a.jmp("drop")

	// Shared port test. A is the source port; the destination port sits two
	// bytes later, reachable from the same X for the IPv4 path. For IPv6 the
	// header is fixed so absolute offsets work; the indirect load below is
	// harmless there because X is zero.
	a.label("udpports")
	a.jeq(53, "accept")
	a.jeq(443, "accept")
	a.jeq(67, "accept")
	a.jeq(68, "accept")
	a.jeq(80, "accept")
	a.jeq(123, "accept")
	a.jeq(5353, "accept")
	a.jeq(1900, "accept")
	a.emit(bpf.LoadIndirect{Off: ethHdrLen + 2, Size: 2}) // dst port (IPv4 path)
	a.jeq(53, "accept")
	a.jeq(443, "accept")
	a.jeq(67, "accept")
	a.jeq(68, "accept")
	a.jeq(80, "accept")
	a.jeq(123, "accept")
	a.jeq(5353, "accept")
	a.jeq(1900, "accept")
	a.jmp("drop")

	a.label("accept")
	a.emit(bpf.RetConstant{Val: uint32(snapLen)})
	a.label("drop")
	a.emit(bpf.RetConstant{Val: 0})

	return a.assemble()
}
