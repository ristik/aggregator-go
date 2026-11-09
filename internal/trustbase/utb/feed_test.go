package utb_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/utbstore"

	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb/utbtest"
)

// chainSource serves the first n epochs of a chain the way a root's store does (gettrustbase.Source).
type chainSource struct {
	c *utbtest.Chain
	n int
}

func (s chainSource) Tip() utbstore.Tip {
	id, _ := s.c.Entries[s.n-1].EntryID()
	return utbstore.Tip{Epoch: uint64(s.n), EntryID: id}
}
func (s chainSource) GenesisEpoch() uint64 { return 1 }
func (s chainSource) Entry(epoch uint64) (*types.RootTrustBaseV2, error) {
	if epoch < 1 || epoch > uint64(s.n) {
		return nil, utbstore.ErrNotFound
	}
	return s.c.Entries[epoch-1], nil
}
func (s chainSource) Range(from, to uint64, maxEntries, maxBytes int) ([][]byte, uint64, bool, error) {
	if from < 1 {
		from = 1
	}
	if to > uint64(s.n) {
		to = uint64(s.n)
	}
	if from > to {
		return nil, 0, false, utbstore.ErrNotFound
	}
	var out [][]byte
	used := 0
	for e := from; e <= to; e++ {
		b := s.c.Raw[e-1]
		if len(out) >= maxEntries || used+len(b) > maxBytes {
			return out, e, true, nil
		}
		out, used = append(out, b), used+len(b)
	}
	return out, 0, false, nil
}

// peers maps a fake peer id to the server behind it; every page request is counted.
type peers struct {
	mu    sync.Mutex
	srv   map[peer.ID]*gettrustbase.Server
	calls []peer.ID
	reqs  []*gettrustbase.Request
}

func newPeers(t *testing.T, maxEntries int, byID map[peer.ID]chainSource) *peers {
	p := &peers{srv: map[peer.ID]*gettrustbase.Server{}}
	for id, src := range byID {
		s, err := gettrustbase.NewServer(src, gettrustbase.Config{MaxEntries: maxEntries})
		require.NoError(t, err)
		p.srv[id] = s
	}
	return p
}

func (p *peers) Page(_ context.Context, id peer.ID, req *gettrustbase.Request) (*gettrustbase.Response, [][]byte, error) {
	p.mu.Lock()
	p.calls, p.reqs = append(p.calls, id), append(p.reqs, req)
	p.mu.Unlock()
	srv, ok := p.srv[id]
	if !ok {
		return nil, nil, errors.New("unreachable")
	}
	resp := srv.Respond(req)
	out := make([][]byte, len(resp.Entries))
	for i, e := range resp.Entries {
		out[i] = e
	}
	return resp, out, nil
}

func TestCommitteeOfAnEpochNotHeldIsUnknownNotTheLatest(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	h := open(t, c, 2, utbtest.NewMemStore())
	e, err := h.Committee(2)
	require.NoError(t, err)
	require.EqualValues(t, 2, e.Epoch)
	_, err = h.Committee(3)
	require.ErrorIs(t, err, utb.ErrUnknownEpoch, "an epoch above the tip is unknown, never answered with the latest entry")
	_, err = h.Committee(0)
	require.ErrorIs(t, err, utb.ErrUnknownEpoch)
}

func TestIngestAppendsInOrderReplaysAndStopsAtAGap(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	h := open(t, c, 1, utbtest.NewMemStore())

	added, gap, err := h.Ingest(ctx, [][]byte{c.Raw[1], c.Raw[2]})
	require.NoError(t, err)
	require.Equal(t, 2, added)
	require.False(t, gap)
	require.EqualValues(t, 3, tipOf(h))

	added, gap, err = h.Ingest(ctx, [][]byte{c.Raw[1], c.Raw[2]})
	require.NoError(t, err)
	require.Zero(t, added, "the same entries again are replays")
	require.False(t, gap)

	added, gap, err = h.Ingest(ctx, [][]byte{c.Raw[3], c.Raw[5]})
	require.NoError(t, err)
	require.Equal(t, 1, added, "epoch 4 is appended, epoch 6 does not follow epoch 4")
	require.True(t, gap)
	require.EqualValues(t, 4, tipOf(h))
}

func TestIngestRefusesAConflictingEntryAndKeepsTheHeldOne(t *testing.T) {
	c := utbtest.NewChain(t, 4, 4, 0)
	fork := utbtest.NewChain(t, 4, 4, 7) // shares the genesis, forks at epoch 2
	h := open(t, c, 3, utbtest.NewMemStore())
	held, id := h.Tip()

	_, _, err := h.Ingest(ctx, [][]byte{fork.Raw[2]})
	require.ErrorIs(t, err, utb.ErrConflict, "a different entry for a held epoch is a conflict")
	e, id2 := h.Tip()
	require.Equal(t, held, e)
	require.Equal(t, id, id2, "the held history is untouched")

	// the rejection is not remembered: the honest continuation is still accepted
	added, _, err := h.Ingest(ctx, [][]byte{c.Raw[3]})
	require.NoError(t, err)
	require.Equal(t, 1, added)
}

func TestIngestSeparatesALocalStoreFailureFromAPeersBadEntry(t *testing.T) {
	c := utbtest.NewChain(t, 4, 4, 0)
	store := utbtest.NewMemStore()
	h := open(t, c, 2, store)
	store.PutHook = func(uint64) (bool, error) { return false, errors.New("disk full") }
	_, _, err := h.Ingest(ctx, [][]byte{c.Raw[2]})
	require.ErrorIs(t, err, utb.ErrLocal)
	require.ErrorIs(t, err, utb.ErrPersist)
	require.EqualValues(t, 2, tipOf(h), "nothing is published when the write fails")

	store.PutHook = nil
	added, _, err := h.Ingest(ctx, [][]byte{c.Raw[2]})
	require.NoError(t, err, "retrying is safe")
	require.Equal(t, 1, added)
}

func TestCatchUpPagesOneEntryAtATimeAndKeepsEveryPrefix(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	h := open(t, c, 1, utbtest.NewMemStore())
	p := newPeers(t, 1, map[peer.ID]chainSource{"root": {c, 6}})

	added, err := h.CatchUp(ctx, p, []peer.ID{"root"}, nil)
	require.NoError(t, err)
	require.Equal(t, 5, added)
	require.EqualValues(t, 6, tipOf(h))
	require.GreaterOrEqual(t, len(p.calls), 5, "maxEntries=1 forces one page per entry (the real range traffic)")
	// the first request starts at the held tip + 1, and later ones echo the frozen snapshot
	require.EqualValues(t, 2, p.reqs[0].FromEpoch)
	require.Nil(t, p.reqs[0].SnapshotEnd)
	require.NotNil(t, p.reqs[1].SnapshotEnd)
	for _, r := range p.reqs[1:] {
		require.EqualValues(t, 6, *r.SnapshotEnd, "no page mixes snapshots")
	}

	// current: nothing newer anywhere
	added, err = h.CatchUp(ctx, p, []peer.ID{"root"}, nil)
	require.NoError(t, err)
	require.Zero(t, added)
}

func TestCatchUpSkipsALaggingAndAHostilePeerAndContinuesFromTheSameCursor(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	fork := utbtest.NewChain(t, 4, 6, 9)
	h := open(t, c, 2, utbtest.NewMemStore())
	p := newPeers(t, 2, map[peer.ID]chainSource{
		"lagging": {c, 2}, // knows nothing newer
		"hostile": {fork, 6},
		"honest":  {c, 6},
	})
	added, err := h.CatchUp(ctx, p, []peer.ID{"lagging", "hostile", "honest"}, nil)
	require.NoError(t, err)
	require.Equal(t, 4, added)
	e, id := h.Tip()
	require.EqualValues(t, 6, e)
	require.Equal(t, c.ID(t, 6), id, "the history followed the honest peer; the forked entries were refused")
}

func TestCatchUpWithOnlyAHostilePeerKeepsTheHeldHistoryAndFails(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	fork := utbtest.NewChain(t, 4, 5, 9)
	h := open(t, c, 3, utbtest.NewMemStore())
	p := newPeers(t, 2, map[peer.ID]chainSource{"hostile": {fork, 5}})
	_, err := h.CatchUp(ctx, p, []peer.ID{"hostile"}, nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, utb.ErrLocal, "a peer's bad history is not a local failure")
	e, id := h.Tip()
	require.EqualValues(t, 3, e)
	require.Equal(t, c.ID(t, 3), id)
}

func TestCatchUpToAnEpochStopsThere(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	h := open(t, c, 1, utbtest.NewMemStore())
	p := newPeers(t, 64, map[peer.ID]chainSource{"root": {c, 6}})
	to := uint64(3)
	added, err := h.CatchUp(ctx, p, []peer.ID{"root"}, &to)
	require.NoError(t, err)
	require.Equal(t, 2, added)
	require.EqualValues(t, 3, tipOf(h))
}

func TestCatchUpStopsAtALocalStoreFailureInsteadOfAskingOtherPeers(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	store := utbtest.NewMemStore()
	h := open(t, c, 2, store)
	store.AdvanceHook = func(uint64) error { return errors.New("disk full") }
	p := newPeers(t, 1, map[peer.ID]chainSource{"a": {c, 6}, "b": {c, 6}, "c": {c, 6}})
	_, err := h.CatchUp(ctx, p, []peer.ID{"a", "b", "c"}, nil)
	require.ErrorIs(t, err, utb.ErrLocal)
	require.Less(t, len(p.calls), 4, "the other peers were not asked for what this process cannot store")
	require.EqualValues(t, 2, tipOf(h))
}

func TestCatchUpIsCancellable(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	h := open(t, c, 1, utbtest.NewMemStore())
	p := newPeers(t, 1, map[peer.ID]chainSource{"root": {c, 6}})
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := h.CatchUp(cctx, p, []peer.ID{"root"}, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 1, tipOf(h))
}

// A verified entry that conflicts with a different successor in the shared store is this deployment's inconsistency, not the fault of the peers that serve
// it: the sync ends as a local failure and asks no second peer, and Ingest reports it the same way.
func TestAVerifiedEntryConflictingWithTheSharedStoreIsLocalNotAPeerFault(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	store := utbtest.NewMemStore()
	a, b := open(t, c, 3, store), open(t, c, 3, store)
	_, err := a.Append(ctx, epoch4(t, bytes.Repeat([]byte{0x55}, 32), []int{0, 1, 2}))
	require.NoError(t, err)

	p := newPeers(t, 2, map[peer.ID]chainSource{"p1": {c, 5}, "p2": {c, 5}})
	added, err := b.CatchUp(ctx, p, []peer.ID{"p1", "p2"}, nil)
	require.ErrorIs(t, err, utb.ErrLocal)
	require.NotErrorIs(t, err, utb.ErrConflict)
	require.Zero(t, added)
	require.Len(t, p.calls, 1, "the honest peers are not blamed: no second peer is asked")
	require.EqualValues(t, 3, tipOf(b))

	_, _, err = b.Ingest(ctx, [][]byte{c.Raw[3]})
	require.ErrorIs(t, err, utb.ErrLocal)
	require.NotErrorIs(t, err, utb.ErrConflict)
}

// slowPeers counts the pages in flight at once and holds each briefly, so two overlapping catch-ups would show.
type slowPeers struct {
	*peers
	mu       sync.Mutex
	inFlight int
	max      int
}

func (p *slowPeers) Page(ctx context.Context, id peer.ID, req *gettrustbase.Request) (*gettrustbase.Response, [][]byte, error) {
	p.mu.Lock()
	p.inFlight++
	if p.inFlight > p.max {
		p.max = p.inFlight
	}
	p.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	defer func() { p.mu.Lock(); p.inFlight--; p.mu.Unlock() }()
	return p.peers.Page(ctx, id, req)
}

func TestOnlyOneCatchUpRunsAtATime(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	h := open(t, c, 1, utbtest.NewMemStore())
	p := &slowPeers{peers: newPeers(t, 1, map[peer.ID]chainSource{"root": {c, 5}})}
	var wg sync.WaitGroup
	total := make([]int, 2)
	for i := range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := h.CatchUp(ctx, p, []peer.ID{"root"}, nil)
			require.NoError(t, err)
			total[i] = n
		}()
	}
	wg.Wait()
	require.Equal(t, 1, p.max, "two catch-ups never fetch at the same time")
	require.Equal(t, 4, total[0]+total[1], "each entry is counted once, by the catch-up that appended it")
	require.EqualValues(t, 5, tipOf(h))
}
