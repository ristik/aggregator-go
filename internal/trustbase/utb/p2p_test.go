package utb_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"

	cryptolibp2p "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/network"

	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb/utbtest"
)

func newLoopbackPeer(t *testing.T) *network.Peer {
	t.Helper()
	priv, pubKey, err := cryptolibp2p.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	privBytes, err := priv.Raw()
	require.NoError(t, err)
	pub, err := pubKey.Raw()
	require.NoError(t, err)
	conf, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, &network.PeerKeyPair{PublicKey: pub, PrivateKey: privBytes}, nil, nil)
	require.NoError(t, err)
	p, err := network.NewPeer(t.Context(), conf, slog.New(slog.DiscardHandler), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// root starts a libp2p peer that answers GetTrustBase for the first n epochs of a chain.
func root(t *testing.T, c *utbtest.Chain, n int) *network.Peer {
	t.Helper()
	p := newLoopbackPeer(t)
	srv, err := gettrustbase.NewServer(chainSource{c, n}, gettrustbase.Config{MaxEntries: 2})
	require.NoError(t, err)
	srv.Register(p)
	return p
}

// A client peer that knows the addresses of the given peers (as a root committee's addresses are known to the aggregator).
func clientOf(t *testing.T, peers ...*network.Peer) (*gettrustbase.Client, []peer.ID) {
	t.Helper()
	cl := newLoopbackPeer(t)
	ids := make([]peer.ID, len(peers))
	for i, p := range peers {
		cl.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), time.Hour)
		ids[i] = p.ID()
	}
	return &gettrustbase.Client{Peer: cl, Timeout: 2 * time.Second}, ids
}

// The feeder's real libp2p path: an unreachable root, a root of another history, a lagging root and an honest one, in that order. The authenticated
// prefix is kept, the forked entries are refused without leaving state behind, and the honest chain is reached.
func TestCatchUpOverLibp2pPastADeadAForkedAndALaggingRoot(t *testing.T) {
	c := utbtest.NewChain(t, 4, 6, 0)
	fork := utbtest.NewChain(t, 4, 6, 9)
	dead := root(t, c, 6)
	hostile, lagging, honest := root(t, fork, 6), root(t, c, 2), root(t, c, 6)
	cl, ids := clientOf(t, dead, hostile, lagging, honest)
	require.NoError(t, dead.Close()) // its address stays known; nothing answers

	// held at epoch 2: the fork diverges at epoch 2 and is signed by the genesis committee, so from epoch 1 it would be a validly signed alternative
	// successor that no verification could tell apart; from epoch 2 its entries do not extend the held tip
	h := open(t, c, 2, utbtest.NewMemStore())
	added, err := h.CatchUp(ctx, cl, ids, nil)
	require.NoError(t, err)
	require.Equal(t, 4, added)
	e, id := h.Tip()
	require.EqualValues(t, 6, e)
	require.Equal(t, c.ID(t, 6), id, "the history is the honest chain, not the forked one")
}

func TestCatchUpOverLibp2pWithOnlyHostileAndDeadRootsKeepsTheHeldHistory(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	fork := utbtest.NewChain(t, 4, 5, 9)
	dead, hostile := root(t, c, 5), root(t, fork, 5)
	cl, ids := clientOf(t, dead, hostile)
	require.NoError(t, dead.Close())

	h := open(t, c, 3, utbtest.NewMemStore())
	_, err := h.CatchUp(ctx, cl, ids, nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, utb.ErrLocal, "peers' faults are not this process's")
	e, id := h.Tip()
	require.EqualValues(t, 3, e)
	require.Equal(t, c.ID(t, 3), id)

	// nothing sticky: the same history then catches up from an honest root
	honest := root(t, c, 5)
	cl2, ids2 := clientOf(t, hostile, honest)
	added, err := h.CatchUp(ctx, cl2, ids2, nil)
	require.NoError(t, err)
	require.Equal(t, 2, added)
}

// A failure of this process's own store ends the sync over the real transport too, instead of blaming and trying every other root.
func TestCatchUpOverLibp2pStopsAtALocalStoreFailure(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	a, b := root(t, c, 5), root(t, c, 5)
	cl, ids := clientOf(t, a, b)
	store := utbtest.NewMemStore()
	h := open(t, c, 2, store)
	store.PutHook = func(uint64) (bool, error) { return false, errors.New("disk full") }

	_, err := h.CatchUp(ctx, cl, ids, nil)
	require.ErrorIs(t, err, utb.ErrLocal)
	require.EqualValues(t, 2, tipOf(h))

	store.PutHook = nil
	added, err := h.CatchUp(ctx, cl, ids, nil)
	require.NoError(t, err, "retrying is safe")
	require.Equal(t, 3, added)
}

func TestCatchUpOverLibp2pIsCancellable(t *testing.T) {
	c := utbtest.NewChain(t, 4, 5, 0)
	cl, ids := clientOf(t, root(t, c, 5))
	h := open(t, c, 1, utbtest.NewMemStore())
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := h.CatchUp(cctx, cl, ids, nil)
	require.Error(t, err)
	require.EqualValues(t, 1, tipOf(h))
}
