// Package utb serves the Unicity Trust Base history (signed record version 2) from a bundle file an operator ships with the deployment.
//
// The history is loaded once, verified completely from an operator-supplied genesis pin and never changes while the process runs. It is not a
// synchronised view of the roots: a newer authority needs a verified replacement bundle and a restart. Respond answers GetTrustBase queries from it
// with the same page semantics as the root peers (statuses, frozen snapshot, paging caps), so a client's fetch loop works against either.
package utb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	// DefaultMaxFileBytes and DefaultMaxEntries are the file budget of a shipped bundle; a release never has a fixed history length.
	DefaultMaxFileBytes = 64 << 20
	DefaultMaxEntries   = 1 << 16
)

// ErrLoad is returned for every reason the configured bundle cannot be used; the aggregator refuses to start.
var ErrLoad = errors.New("trust-base bundle refused")

// LoadConfig is what the operator configures.
type LoadConfig struct {
	Path string
	// Pin is the genesis EntryID, from authenticated operator configuration; it is never computed from the file.
	Pin [types.TrustBaseV2IDLen]byte
	// Network is the network the aggregator serves, from independent configuration (never taken from the bundle).
	Network types.NetworkID
	// MaxFileBytes and MaxEntries bound the read; zero takes the defaults.
	MaxFileBytes int
	MaxEntries   int
}

// History is a verified complete trust-base history.
type History struct {
	network types.NetworkID
	genesis uint64
	raw     [][]byte
	entries []*types.RootTrustBaseV2
	ids     [][types.TrustBaseV2IDLen]byte
}

// Load reads, strictly decodes and fully verifies the bundle: the genesis is the pinned identity, every later entry carries a strict quorum of its
// predecessor's members, the history is complete from the genesis, the network is the configured one and a page can carry one maximum-size entry.
func Load(cfg LoadConfig) (*History, error) {
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = DefaultMaxFileBytes
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.Network == 0 {
		return nil, fmt.Errorf("%w: no expected network configured", ErrLoad)
	}
	data, err := readBounded(cfg.Path, cfg.MaxFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLoad, err)
	}
	b, err := types.DecodeTrustBaseBundle(data, types.TrustBaseLimits{MaxBytes: cfg.MaxFileBytes, MaxEntries: cfg.MaxEntries})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLoad, err)
	}
	if err := types.VerifyTrustBaseBundle(b, cfg.Pin); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLoad, err)
	}
	if b.Network != cfg.Network {
		return nil, fmt.Errorf("%w: the bundle is of network %d, this aggregator serves network %d", ErrLoad, b.Network, cfg.Network)
	}
	if types.MaxTrustBaseEntryBytes+types.TrustBaseResponseEnvelopeBound > types.DefaultTrustBaseMaxResponse {
		return nil, fmt.Errorf("%w: a page cannot carry one maximum-size entry", ErrLoad)
	}
	h := &History{network: b.Network, genesis: b.Entries[0].Epoch, raw: b.Raw, entries: b.Entries, ids: make([][types.TrustBaseV2IDLen]byte, len(b.Entries))}
	for i, e := range b.Entries {
		if h.ids[i], err = e.EntryID(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrLoad, err)
		}
	}
	return h, nil
}

// readBounded reads a whole file but never more than max bytes.
func readBounded(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("%s is larger than the %d byte budget", path, max)
	}
	return data, nil
}

// Network is the network of the history.
func (h *History) Network() types.NetworkID { return h.network }

// GenesisEpoch is the epoch of the first entry.
func (h *History) GenesisEpoch() uint64 { return h.genesis }

// Tip is the latest entry served.
func (h *History) Tip() (epoch uint64, id [types.TrustBaseV2IDLen]byte) {
	last := len(h.entries) - 1
	return h.entries[last].Epoch, h.ids[last]
}

// Entry returns the entry of an epoch, or nil outside the history.
func (h *History) Entry(epoch uint64) *types.RootTrustBaseV2 {
	if epoch < h.genesis || epoch-h.genesis >= uint64(len(h.entries)) {
		return nil
	}
	return h.entries[epoch-h.genesis]
}

// Query is a parsed GET: the HTTP request carries no network and no byte budget (the page is capped at 1 MiB), so a client compares the response's
// network with its own.
type Query struct {
	From            uint64
	To              *uint64
	SnapshotEnd     *uint64
	SnapshotEntryID []byte
	MaxEntries      int // 1..DefaultTrustBaseMaxEntries
}

func (h *History) reply(st types.TrustBaseStatus) *types.TrustBaseResponse {
	return &types.TrustBaseResponse{Version: types.TrustBaseResponseVersion, Network: h.network, Status: st}
}

// Unavailable is the answer while the history cannot be trusted to agree with the aggregator's own authority.
func (h *History) Unavailable() *types.TrustBaseResponse {
	return h.reply(types.TrustBaseStatusUnavailable)
}

// Respond answers one query from the history.
//
// The first page takes the tip as its snapshot (or the requested end, clamped to the tip) and echoes (effectiveEnd, endEntryID); later pages send
// them back as snapshotEnd/snapshotEntryId, so the end does not move. A replica whose history stops short of the snapshot answers NotYetAvailable,
// one with another entry at that epoch HistoryMismatch. `from` beyond the end is NotYetAvailable with the actual tip. A page is a contiguous
// ascending prefix within the entry and byte budgets, never empty.
func (h *History) Respond(q Query) *types.TrustBaseResponse {
	if q.MaxEntries < 1 || q.MaxEntries > types.DefaultTrustBaseMaxEntries ||
		q.From < h.genesis || (q.To != nil && *q.To < q.From) ||
		(q.SnapshotEnd == nil) != (q.SnapshotEntryID == nil) ||
		(q.SnapshotEnd != nil && (len(q.SnapshotEntryID) != types.TrustBaseV2IDLen || q.From > *q.SnapshotEnd ||
			(q.To != nil && *q.To < *q.SnapshotEnd))) {
		return h.reply(types.TrustBaseStatusInvalidRequest)
	}
	tipEpoch, tipID := h.Tip()
	end, endID := tipEpoch, tipID
	switch {
	case q.SnapshotEnd != nil:
		if tipEpoch < *q.SnapshotEnd {
			r := h.reply(types.TrustBaseStatusNotYetAvailable)
			r.FromEpoch, r.EffectiveEnd, r.EndEntryID = q.From, tipEpoch, tipID[:]
			return r
		}
		id := h.ids[*q.SnapshotEnd-h.genesis]
		if !bytes.Equal(id[:], q.SnapshotEntryID) {
			return h.reply(types.TrustBaseStatusHistoryMismatch)
		}
		end, endID = *q.SnapshotEnd, id
	case q.To != nil && *q.To < end:
		end, endID = *q.To, h.ids[*q.To-h.genesis]
	}
	if q.From > end {
		r := h.reply(types.TrustBaseStatusNotYetAvailable)
		r.FromEpoch, r.EffectiveEnd, r.EndEntryID = q.From, tipEpoch, tipID[:]
		return r
	}

	budget := types.DefaultTrustBaseMaxResponse - types.TrustBaseResponseEnvelopeBound
	r := h.reply(types.TrustBaseStatusOK)
	r.FromEpoch, r.EffectiveEnd, r.EndEntryID = q.From, end, endID[:]
	used := 0
	epoch := q.From
	for ; epoch <= end && len(r.Entries) < q.MaxEntries; epoch++ {
		raw := h.raw[epoch-h.genesis]
		if used+len(raw) > budget {
			break
		}
		used += len(raw)
		r.Entries = append(r.Entries, raw)
	}
	if len(r.Entries) == 0 {
		return h.reply(types.TrustBaseStatusLimitTooSmall)
	}
	if epoch <= end {
		next := epoch
		r.NextEpoch = &next
	}
	return r
}
