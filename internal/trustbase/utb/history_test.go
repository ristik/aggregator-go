package utb

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/storage/interfaces"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb/utbtest"
)

func u64(v uint64) *uint64 { return &v }

func load(t *testing.T, c *utbtest.Chain, n int) *History {
	t.Helper()
	h, err := Load(LoadConfig{Path: utbtest.WriteFile(t, "b.cbor", c.Bundle(t, n)), Pin: c.Pin(t), Network: utbtest.Network})
	require.NoError(t, err)
	return h
}

// decoded proves every answer is a well-formed response under the shared codec and returns it with its entries.
func decoded(t *testing.T, r *types.TrustBaseResponse) []*types.RootTrustBaseV2 {
	t.Helper()
	b, err := r.Encode()
	require.NoError(t, err)
	got, entries, err := types.DecodeTrustBaseResponse(b, types.TrustBasePageLimits)
	require.NoError(t, err)
	require.Equal(t, r.Status, got.Status)
	return entries
}

func TestLoadRefusesEverythingThatIsNotTheConfiguredCompleteHistory(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	good := c.Bundle(t, 6)
	cfg := func(data []byte) LoadConfig {
		return LoadConfig{Path: utbtest.WriteFile(t, "b.cbor", data), Pin: c.Pin(t), Network: utbtest.Network}
	}
	_, err := Load(cfg(good))
	require.NoError(t, err)

	// the encoder itself refuses a partial range, so the file is built by hand: epochs 3..6, a page that ends at the tip with no cursor
	id6 := c.ID(t, 6)
	partial := &types.TrustBaseResponse{Version: 1, Network: utbtest.Network, Status: types.TrustBaseStatusOK, FromEpoch: 3, EffectiveEnd: 6, EndEntryID: id6[:]}
	for _, r := range c.Raw[2:] {
		partial.Entries = append(partial.Entries, r)
	}
	partialBytes, err := partial.Encode()
	require.NoError(t, err)
	_, err = Load(cfg(partialBytes))
	require.ErrorIs(t, err, ErrLoad, "a partial range")

	wrongPin := cfg(good)
	wrongPin.Pin[0] ^= 1
	_, err = Load(wrongPin)
	require.ErrorIs(t, err, ErrLoad, "wrong pin")

	otherNet := cfg(good)
	otherNet.Network = utbtest.Network + 1
	_, err = Load(otherNet)
	require.ErrorIs(t, err, ErrLoad, "wrong network")
	require.Contains(t, err.Error(), "network")

	noNet := cfg(good)
	noNet.Network = 0
	_, err = Load(noNet)
	require.ErrorIs(t, err, ErrLoad, "no expected network")

	_, err = Load(cfg(append(bytes.Clone(good), 0)))
	require.ErrorIs(t, err, ErrLoad, "trailing bytes")
	_, err = Load(cfg(good[:len(good)-1]))
	require.ErrorIs(t, err, ErrLoad, "truncated")
	_, err = Load(cfg(nil))
	require.ErrorIs(t, err, ErrLoad, "empty file")

	_, err = Load(LoadConfig{Path: "/no/such/file", Pin: c.Pin(t), Network: utbtest.Network})
	require.ErrorIs(t, err, ErrLoad, "missing file")

	small := cfg(good)
	small.MaxFileBytes = len(good) - 1
	_, err = Load(small)
	require.ErrorIs(t, err, ErrLoad, "file over the byte budget")
	few := cfg(good)
	few.MaxEntries = 5
	_, err = Load(few)
	require.ErrorIs(t, err, ErrLoad, "more entries than the budget")

	// a quorum short by one in epoch 4 (the structure and links are fine, the signatures are not)
	weak := utbtest.NewChain(t, 4, 6, 0)
	weak.Entries[3].Signatures = nil
	for i := 0; i < 2; i++ {
		require.NoError(t, weak.Entries[3].Sign(weak.Entries[2].RootNodes[i].NodeID, weak.Signers[i]))
	}
	raw := append([][]byte{}, weak.Raw...)
	var err2 error
	raw[3], err2 = weak.Entries[3].MarshalCBOR()
	require.NoError(t, err2)
	// the successor links by EntryID, which does not depend on the signatures, so the chain still encodes
	data, err := types.EncodeTrustBaseBundle(raw)
	require.NoError(t, err)
	_, err = Load(LoadConfig{Path: utbtest.WriteFile(t, "w.cbor", data), Pin: c.Pin(t), Network: utbtest.Network})
	require.ErrorIs(t, err, ErrLoad, "short quorum")
	require.Contains(t, err.Error(), "epoch 4")
}

func TestLoadAcceptsALargeCommitteeInASingleEntryBundle(t *testing.T) {
	c := utbtest.NewChain(t, 256, 1, 0)
	h := load(t, c, 1)
	require.Len(t, h.Entry(1).RootNodes, 256)
}

func TestRespondStatusesAndShapes(t *testing.T) {
	c := utbtest.NewChain(t, 4, 7, 0)
	h := load(t, c, 7)
	tip := c.ID(t, 7)
	q := func(from uint64) Query { return Query{From: from, MaxEntries: 64} }

	t.Run("the complete history", func(t *testing.T) {
		r := h.Respond(q(1))
		require.Equal(t, types.TrustBaseStatusOK, r.Status)
		require.Equal(t, utbtest.Network, r.Network)
		require.Equal(t, uint64(1), r.FromEpoch)
		require.Equal(t, uint64(7), r.EffectiveEnd)
		require.Equal(t, tip[:], r.EndEntryID)
		require.Nil(t, r.NextEpoch)
		require.Len(t, decoded(t, r), 7)
	})
	t.Run("a range from the middle, and the tip alone", func(t *testing.T) {
		require.Len(t, decoded(t, h.Respond(q(4))), 4)
		es := decoded(t, h.Respond(q(7)))
		require.Len(t, es, 1)
		require.Equal(t, uint64(7), es[0].Epoch)
	})
	t.Run("an end below the tip", func(t *testing.T) {
		r := h.Respond(Query{From: 2, To: u64(4), MaxEntries: 64})
		id4 := c.ID(t, 4)
		require.Equal(t, uint64(4), r.EffectiveEnd)
		require.Equal(t, id4[:], r.EndEntryID)
		require.Len(t, decoded(t, r), 3)
	})
	t.Run("an end beyond the tip is clamped, not an error", func(t *testing.T) {
		r := h.Respond(Query{From: 5, To: u64(1000), MaxEntries: 64})
		require.Equal(t, types.TrustBaseStatusOK, r.Status)
		require.Equal(t, uint64(7), r.EffectiveEnd)
		require.Len(t, decoded(t, r), 3)
	})
	t.Run("from beyond the tip is NotYetAvailable with the actual tip", func(t *testing.T) {
		r := h.Respond(q(8))
		require.Equal(t, types.TrustBaseStatusNotYetAvailable, r.Status)
		require.Equal(t, uint64(7), r.EffectiveEnd)
		require.Equal(t, tip[:], r.EndEntryID)
		require.Empty(t, r.Entries)
		decoded(t, r)
		// also when the requested end is below from's reach
		r = h.Respond(Query{From: 9, To: u64(12), MaxEntries: 64})
		require.Equal(t, types.TrustBaseStatusNotYetAvailable, r.Status)
	})
	t.Run("invalid requests", func(t *testing.T) {
		for name, qq := range map[string]Query{
			"from below the genesis":      {From: 0, MaxEntries: 64},
			"end below from":              {From: 4, To: u64(3), MaxEntries: 64},
			"snapshot id without end":     {From: 1, SnapshotEntryID: tip[:], MaxEntries: 64},
			"snapshot end without id":     {From: 1, SnapshotEnd: u64(7), MaxEntries: 64},
			"short snapshot id":           {From: 1, SnapshotEnd: u64(7), SnapshotEntryID: tip[:5], MaxEntries: 64},
			"from beyond the snapshot":    {From: 8, SnapshotEnd: u64(7), SnapshotEntryID: tip[:], MaxEntries: 64},
			"end below the snapshot":      {From: 1, To: u64(5), SnapshotEnd: u64(7), SnapshotEntryID: tip[:], MaxEntries: 64},
			"no entries allowed":          {From: 1, MaxEntries: 0},
			"more entries than the limit": {From: 1, MaxEntries: 65},
		} {
			r := h.Respond(qq)
			require.Equal(t, types.TrustBaseStatusInvalidRequest, r.Status, name)
			require.Empty(t, r.Entries, name)
			decoded(t, r)
		}
	})
	t.Run("unavailable carries nothing", func(t *testing.T) {
		r := h.Unavailable()
		require.Equal(t, types.TrustBaseStatusUnavailable, r.Status)
		decoded(t, r)
	})
}

// A client pages through the history by echoing (effectiveEnd, endEntryID) as the snapshot; the end must not move and the cursor must advance
// strictly to the end.
func TestPagingFreezesTheSnapshotAndAdvancesStrictly(t *testing.T) {
	c := utbtest.NewChain(t, 4, 9, 0)
	h := load(t, c, 9)

	var got []uint64
	query := Query{From: 1, MaxEntries: 2}
	pages := 0
	var end uint64
	for {
		r := h.Respond(query)
		require.Equal(t, types.TrustBaseStatusOK, r.Status)
		if pages == 0 {
			end = r.EffectiveEnd
			require.Equal(t, uint64(9), end)
		}
		require.Equal(t, end, r.EffectiveEnd, "the end does not move")
		for _, e := range decoded(t, r) {
			got = append(got, e.Epoch)
		}
		pages++
		require.LessOrEqual(t, pages, 5, "no progress")
		if r.NextEpoch == nil {
			break
		}
		require.Equal(t, got[len(got)-1]+1, *r.NextEpoch, "the cursor is the next epoch")
		query = Query{From: *r.NextEpoch, MaxEntries: 2, SnapshotEnd: u64(r.EffectiveEnd), SnapshotEntryID: r.EndEntryID}
	}
	require.Equal(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}, got)
	require.Equal(t, 5, pages)
}

func TestAnOlderReplicaAndAnotherHistoryDuringAFrozenSnapshot(t *testing.T) {
	c := utbtest.NewChain(t, 4, 9, 0)
	full, behind := load(t, c, 9), load(t, c, 5)
	id9 := c.ID(t, 9)

	snap := Query{From: 6, MaxEntries: 64, SnapshotEnd: u64(9), SnapshotEntryID: id9[:]}
	require.Equal(t, types.TrustBaseStatusOK, full.Respond(snap).Status)

	r := behind.Respond(snap)
	require.Equal(t, types.TrustBaseStatusNotYetAvailable, r.Status, "a replica behind the frozen end")
	require.Equal(t, uint64(5), r.EffectiveEnd, "it reports its own tip")
	decoded(t, r)
}

func TestAHistoryWithAnotherEntryAtTheSnapshotEpochIsAMismatch(t *testing.T) {
	a := utbtest.NewChain(t, 4, 9, 0)
	// b shares a's genesis and epochs 1..8 and differs at epoch 9 only
	b := utbtest.NewChain(t, 4, 9, 0)
	b.Entries[8].StateHash = bytes.Repeat([]byte{0x77}, 32)
	b.Entries[8].Signatures = nil
	for i := 0; i < int(b.Entries[8].QuorumThreshold); i++ {
		require.NoError(t, b.Entries[8].Sign(b.Entries[7].RootNodes[i].NodeID, b.Signers[i]))
	}
	raw, err := b.Entries[8].MarshalCBOR()
	require.NoError(t, err)
	b.Raw[8] = raw

	ha, hb := load(t, a, 9), load(t, b, 9)
	idA := a.ID(t, 9)
	r := hb.Respond(Query{From: 5, MaxEntries: 64, SnapshotEnd: u64(9), SnapshotEntryID: idA[:]})
	require.Equal(t, types.TrustBaseStatusHistoryMismatch, r.Status)
	require.Empty(t, r.Entries)
	decoded(t, r)
	require.Equal(t, types.TrustBaseStatusOK, ha.Respond(Query{From: 5, MaxEntries: 64, SnapshotEnd: u64(9), SnapshotEntryID: idA[:]}).Status)
}

// With a large committee every entry is tens of kilobytes: a page ends at the byte budget long before the 64-entry cap, and the cursor continues.
func TestAPageEndsAtTheByteBudgetWithALargeCommittee(t *testing.T) {
	c := utbtest.NewChain(t, 256, 52, 0)
	h := load(t, c, 52)
	r := h.Respond(Query{From: 1, MaxEntries: 64})
	require.Equal(t, types.TrustBaseStatusOK, r.Status)
	require.NotNil(t, r.NextEpoch, "52 large entries do not fit one page")
	require.Less(t, len(r.Entries), 52)
	body, err := r.Encode()
	require.NoError(t, err)
	require.LessOrEqual(t, len(body), types.DefaultTrustBaseMaxResponse)
	// the next entry would not have fitted
	next := h.raw[*r.NextEpoch-1]
	used := 0
	for _, e := range r.Entries {
		used += len(e)
	}
	require.Greater(t, used+len(next), types.DefaultTrustBaseMaxResponse-types.TrustBaseResponseEnvelopeBound)

	var epochs []uint64
	query := Query{From: 1, MaxEntries: 64}
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		r := h.Respond(query)
		for _, e := range decoded(t, r) {
			epochs = append(epochs, e.Epoch)
		}
		if r.NextEpoch == nil {
			break
		}
		query = Query{From: *r.NextEpoch, MaxEntries: 64, SnapshotEnd: u64(r.EffectiveEnd), SnapshotEntryID: r.EndEntryID}
	}
	require.Len(t, epochs, 52)
}

func TestCheckAuthorityComparesTheFieldsBothRecordsCarry(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	h := load(t, c, 5)
	require.NoError(t, h.CheckAuthority(c.V1(3)))

	edit := func(f func(v1 *types.RootTrustBaseV1)) error {
		v1 := c.V1(3)
		v1.RootNodes = append([]*types.NodeInfo{}, v1.RootNodes...)
		f(v1)
		return h.CheckAuthority(v1)
	}
	for name, f := range map[string]func(*types.RootTrustBaseV1){
		"network":      func(v *types.RootTrustBaseV1) { v.NetworkID++ },
		"epoch start":  func(v *types.RootTrustBaseV1) { v.EpochStart++ },
		"threshold":    func(v *types.RootTrustBaseV1) { v.QuorumThreshold-- },
		"a member out": func(v *types.RootTrustBaseV1) { v.RootNodes = v.RootNodes[1:] },
		"stake": func(v *types.RootTrustBaseV1) {
			v.RootNodes[0] = &types.NodeInfo{NodeID: v.RootNodes[0].NodeID, SigKey: v.RootNodes[0].SigKey, Stake: v.RootNodes[0].Stake + 1}
		},
		"key": func(v *types.RootTrustBaseV1) {
			v.RootNodes[0] = &types.NodeInfo{NodeID: v.RootNodes[0].NodeID, SigKey: c.Entries[0].RootNodes[1].SigKey, Stake: v.RootNodes[0].Stake}
		},
		"node id": func(v *types.RootTrustBaseV1) {
			v.RootNodes[0] = &types.NodeInfo{NodeID: "zzz", SigKey: v.RootNodes[0].SigKey, Stake: v.RootNodes[0].Stake}
		},
	} {
		require.ErrorIs(t, edit(f), ErrAuthority, name)
	}
	// an epoch the history does not cover
	require.ErrorIs(t, h.CheckAuthority(utbtest.NewChain(t, 4, 7, 0).V1(7)), ErrAuthority)
}

func TestTheGuardDegradesWhenTheAggregatorsAuthorityMovesPastTheFile(t *testing.T) {
	c := utbtest.NewChain(t, 4, 7, 0)
	h := load(t, c, 5) // the file stops at epoch 5
	var latest *types.RootTrustBaseV1
	var failure error
	calls := 0
	g := NewGuard(h, func(context.Context) (*types.RootTrustBaseV1, error) {
		calls++
		if failure != nil {
			return nil, failure
		}
		if latest == nil {
			return nil, interfaces.ErrTrustBaseNotFound
		}
		return latest, nil
	})
	ctx := context.Background()

	require.NoError(t, g.Check(ctx), "nothing installed yet: nothing to contradict")
	latest = c.V1(5)
	require.NoError(t, g.Check(ctx))
	require.NoError(t, g.Check(ctx))
	latest = c.V1(6) // PUT or the BFT admission moved the active authority; the file did not
	require.ErrorIs(t, g.Check(ctx), ErrAuthority)
	require.ErrorIs(t, g.Check(ctx), ErrAuthority, "remembered for the same head epoch")

	// a transient read failure is reported and not remembered
	failure = errors.New("db down")
	require.Error(t, g.Check(ctx))
	failure = nil
	latest = c.V1(5)
	require.NoError(t, g.Check(ctx), "a later head that the file covers is served again")
	require.Greater(t, calls, 4)
}

func TestCheckInstalledAtStartup(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	h := load(t, c, 6)
	ctx := context.Background()
	list := func(all ...*types.RootTrustBaseV1) func(context.Context, uint64, uint64) ([]*types.RootTrustBaseV1, error) {
		return func(_ context.Context, from, to uint64) ([]*types.RootTrustBaseV1, error) {
			var out []*types.RootTrustBaseV1
			for _, v := range all {
				if v.GetEpoch() >= from && v.GetEpoch() <= to {
					out = append(out, v)
				}
			}
			return out, nil
		}
	}
	head := func(v *types.RootTrustBaseV1) LatestV1 {
		return func(context.Context) (*types.RootTrustBaseV1, error) { return v, nil }
	}

	require.NoError(t, NewGuard(h, head(c.V1(4))).CheckInstalled(ctx, list(c.V1(1), c.V1(2), c.V1(3), c.V1(4))))
	require.NoError(t, NewGuard(h, func(context.Context) (*types.RootTrustBaseV1, error) { return nil, interfaces.ErrTrustBaseNotFound }).
		CheckInstalled(ctx, list()), "empty V1 store")

	// an older installed epoch that contradicts the history, while the head agrees
	bad := c.V1(2)
	bad.EpochStart += 7
	require.ErrorIs(t, NewGuard(h, head(c.V1(4))).CheckInstalled(ctx, list(c.V1(1), bad, c.V1(3), c.V1(4))), ErrAuthority)

	// the active epoch is beyond the file
	long := utbtest.NewChain(t, 4, 8, 0)
	require.ErrorIs(t, NewGuard(h, head(long.V1(8))).CheckInstalled(ctx, list(long.V1(8))), ErrAuthority)

	// the other network
	otherNet := c.V1(4)
	otherNet.NetworkID++
	require.ErrorIs(t, NewGuard(h, head(otherNet)).CheckInstalled(ctx, list(otherNet)), ErrAuthority)
}
