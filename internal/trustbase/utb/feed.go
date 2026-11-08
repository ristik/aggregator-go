package utb

import (
	"context"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// The live source of the history (briefs/pos-utb-live-source-plan.md): entries arrive attached to certification responses (Ingest) and, for a gap, from the
// roots' GetTrustBase protocol (CatchUp). Both go through the one append path, Append: every entry is verified strictly from the held tip, persisted
// before it is served, and a held epoch is never replaced.
//
// Faults are classified. An entry a peer supplied that the history refuses (a conflict, a gap, a bad chain) is the PEER's: it is rejected and reported,
// never remembered, and never changes what is held, because a conflict is detected from the EntryID alone, before the candidate's signatures are
// verified; only an independently authenticated conflicting history could justify more, and nothing here decides that. A failure of the local durable store
// (ErrPersist, ErrStore) is this process's and is returned as ErrLocal, never as a reason to try another peer.

var (
	// ErrUnknownEpoch: no held entry for the epoch; the caller catches up and retries, and nothing advances meanwhile.
	ErrUnknownEpoch = errors.New("utb: no held trust-base entry for the epoch")
	// ErrLocal wraps a failure of this process's own store.
	ErrLocal = errors.New("utb: local trust-base store failure")
)

// Committee is the held entry of an epoch: the committee that signs that epoch's certificates. It is an authority only for its own epoch; a held future
// entry does not mean its committee is reachable yet.
func (h *History) Committee(epoch uint64) (*types.RootTrustBaseV2, error) {
	if e := h.Entry(epoch); e != nil {
		return e, nil
	}
	return nil, fmt.Errorf("%w %d", ErrUnknownEpoch, epoch)
}

// peerFault reports whether an Append error is the fault of the entry's supplier.
func peerFault(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(err, ErrGap) || errors.Is(err, ErrChain)
}

func localFault(err error) error {
	if errors.Is(err, ErrPersist) || errors.Is(err, ErrStore) {
		return fmt.Errorf("%w: %w", ErrLocal, err)
	}
	return nil
}

// Ingest appends the entries attached to a certification response, in order. It returns the number newly appended and whether an entry did not follow the
// held tip (the caller then catches up). An entry the history refuses stops the update and is returned as an error (a peer fault, or ErrLocal); it never
// affects the certificate, which is judged separately.
func (h *History) Ingest(ctx context.Context, updates [][]byte) (added int, gap bool, err error) {
	for _, raw := range updates {
		out, err := h.Append(ctx, raw)
		switch {
		case err == nil:
			if out == Appended {
				added++
			}
		case errors.Is(err, ErrGap):
			return added, true, nil
		default:
			if l := localFault(err); l != nil {
				return added, false, l
			}
			return added, false, err
		}
	}
	return added, false, nil
}

// feedSink is the history as gettrustbase.Sync's sink: Append carries the sync's context and remembers a local failure, which also ends the sync (another peer
// cannot cure this process's store).
type feedSink struct {
	ctx    context.Context
	cancel context.CancelFunc
	h      *History
	local  error
	added  int // entries this sync appended itself (an entry a concurrent Ingest appended first is not counted)
}

func (s *feedSink) Tip() utbstore.Tip {
	epoch, id := s.h.Tip()
	return utbstore.Tip{Epoch: epoch, EntryID: id}
}

func (s *feedSink) Append(raw []byte) (bool, error) {
	out, err := s.h.Append(s.ctx, raw)
	if err != nil {
		if l := localFault(err); l != nil {
			s.local = l
			s.cancel()
			return false, l
		}
		return false, err
	}
	if out == Appended {
		s.added++
	}
	return out == Appended, nil
}

// CatchUp fetches the entries after the held tip from the given root peers (GetTrustBase), up to epoch "to" when it is given, authenticating every entry
// from the one before it. Authenticated prefixes are kept when a later page fails, and the range is never probed beyond what the peers serve from the held
// tip. It returns how many entries this call newly appended (not those a concurrent Ingest appended). One catch-up runs at a time. A failure of the local store is returned as ErrLocal.
func (h *History) CatchUp(ctx context.Context, f gettrustbase.Fetcher, peers []peer.ID, to *uint64) (int, error) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sink := &feedSink{ctx: sctx, cancel: cancel, h: h}
	_, err := gettrustbase.Sync(sctx, f, sink, peers, gettrustbase.SyncOptions{Network: h.network, To: to})
	if sink.local != nil {
		return sink.added, sink.local
	}
	return sink.added, err
}
