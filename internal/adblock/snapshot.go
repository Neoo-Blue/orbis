package adblock

import (
	"bufio"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"os"
)

// Reading every list row back out of SQLite takes minutes on a Raspberry Pi,
// and until it finishes every lookup is unfiltered. The built index is plain
// arrays, so it is kept on disk and a restart is filtering again within
// seconds. The file is only a cache: anything wrong with it means the slow
// rebuild runs instead.

// indexVersion changes when the hash or the layout does.
const indexVersion = 2

type savedRegex struct {
	Pattern, Source, Category string
	Important, Local          bool
}

type savedEntry struct {
	Source, Category string
	Important, Local bool
}

type savedHeader struct {
	Version int
	// Fingerprint names what the index was built from; see Manager.fingerprint.
	Fingerprint  string
	Count        int
	Entries      []savedEntry
	Regexes      []savedRegex
	AllowRegexes []savedRegex
}

func (s *domainSet) write(w *bufio.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, []uint64{uint64(s.n), uint64(len(s.keys))}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, s.keys); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, s.vals)
}

// read loads one table. A table the file cannot hold, or one with no empty
// slot, would otherwise exhaust memory or spin a lookup forever on the DNS path.
func (s *domainSet) read(r *bufio.Reader, fileSize int64) error {
	var head [2]uint64
	if err := binary.Read(r, binary.LittleEndian, &head); err != nil {
		return err
	}
	size := head[1]
	if size&(size-1) != 0 || size > uint64(fileSize)/12 || head[0] >= max(size, 1) {
		return fmt.Errorf("bad table size %d", size)
	}
	s.n, s.keys, s.vals = int(head[0]), make([]uint64, size), make([]uint32, size)
	if err := binary.Read(r, binary.LittleEndian, s.keys); err != nil {
		return err
	}
	used := 0
	for _, k := range s.keys {
		if k != 0 {
			used++
		}
	}
	if used != s.n {
		return fmt.Errorf("table says %d entries, holds %d", s.n, used)
	}
	return binary.Read(r, binary.LittleEndian, s.vals)
}

// SaveIndex writes the list index to path, atomically.
func (m *Matcher) SaveIndex(path, fingerprint string) error {
	idx := m.idx.Load()
	head := savedHeader{Version: indexVersion, Fingerprint: fingerprint, Count: idx.count}
	for _, e := range idx.entries {
		head.Entries = append(head.Entries, savedEntry{e.source, e.category, e.important, e.local})
	}
	for _, r := range idx.regexes {
		head.Regexes = append(head.Regexes, savedRegex{Pattern: r.re.pattern, Source: r.source, Category: r.category, Important: r.important})
	}
	for _, r := range idx.allowRegexes {
		head.AllowRegexes = append(head.AllowRegexes, savedRegex{Pattern: r.re.pattern, Source: r.source, Local: r.local})
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	if err := gob.NewEncoder(w).Encode(head); err != nil {
		return err
	}
	for _, s := range []*domainSet{&idx.exact, &idx.wildcard, &idx.allowExact, &idx.allowWildcard} {
		if err := s.write(w); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadIndex replaces the list index with one saved by SaveIndex and returns the
// fingerprint it was saved with, for the caller to judge how current it is.
func (m *Matcher) LoadIndex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var head savedHeader
	if err := gob.NewDecoder(r).Decode(&head); err != nil {
		return "", err
	}
	if head.Version != indexVersion {
		return "", fmt.Errorf("index version %d, want %d", head.Version, indexVersion)
	}
	idx := newIndex()
	idx.ids, idx.count = nil, head.Count
	for _, e := range head.Entries {
		idx.entries = append(idx.entries, entry{e.Source, e.Category, e.Important, e.Local})
	}
	for _, s := range []*domainSet{&idx.exact, &idx.wildcard, &idx.allowExact, &idx.allowWildcard} {
		if err := s.read(r, info.Size()); err != nil {
			return "", err
		}
		for i, k := range s.keys {
			if k != 0 && int(s.vals[i]) >= len(idx.entries) {
				return "", fmt.Errorf("entry %d out of range", s.vals[i])
			}
		}
	}
	for _, sr := range head.Regexes {
		re, err := compileRegex(sr.Pattern)
		if err != nil {
			return "", err
		}
		idx.regexes = append(idx.regexes, regexEntry{re: re, source: sr.Source, category: sr.Category, important: sr.Important})
	}
	for _, sr := range head.AllowRegexes {
		re, err := compileRegex(sr.Pattern)
		if err != nil {
			return "", err
		}
		idx.allowRegexes = append(idx.allowRegexes, allowRegex{re: re, local: sr.Local, source: sr.Source})
	}
	m.buildMu.Lock()
	m.idx.Store(idx)
	m.buildMu.Unlock()
	return head.Fingerprint, nil
}
