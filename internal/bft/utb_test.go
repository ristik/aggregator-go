package bft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
	"github.com/unicitynetwork/bft-go-base/types"
	bfthex "github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/aggregator-go/internal/config"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/storage/interfaces"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb/utbtest"
)

// threeEpochs is a client holding only the genesis of a three-epoch chain and an in-process root holding all three entries.
func threeEpochs(t *testing.T, partition types.PartitionID) (*BFTClientImpl, *utb.History, *gettrustbase.Server, []fixtureMember, []byte, []byte) {
	t.Helper()
	const net types.NetworkID = 5
	k, j, l := fixtureMembers(t, 4), fixtureMembers(t, 4), fixtureMembers(t, 4)
	g := fixtureEntryOf(t, net, 1, 1, k, nil, nil)
	e2 := fixtureEntryOf(t, net, 2, 100, j, g, k[:3])
	e3 := fixtureEntryOf(t, net, 3, 200, l, e2, j[:3])
	graw, err := g.MarshalCBOR()
	require.NoError(t, err)
	e2raw, err := e2.MarshalCBOR()
	require.NoError(t, err)
	e3raw, err := e3.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	h := openHistory(t, [][]byte{graw}, gid)
	root := openHistory(t, [][]byte{graw, e2raw, e3raw}, gid)
	srv, err := gettrustbase.NewServer(rawSource{raws: [][]byte{graw, e2raw, e3raw}, entries: []*types.RootTrustBaseV2{g, e2, e3}}, gettrustbase.Config{})
	require.NoError(t, err)
	_ = root

	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	c, err := NewBFTClient(context.Background(), &config.BFTConfig{ShardConf: &types.PartitionDescriptionRecord{NetworkID: net, PartitionID: partition}}, nil, NewUTBProvider(h), nil, log, nil)
	require.NoError(t, err)
	return c, h, srv, j, e2raw, e3raw
}

type countingFetcher struct {
	inner gettrustbase.Fetcher
	calls int
}

func (f *countingFetcher) Page(ctx context.Context, id peer.ID, r *gettrustbase.Request) (*gettrustbase.Response, [][]byte, error) {
	f.calls++
	return f.inner.Page(ctx, id, r)
}

func woken(c *BFTClientImpl) bool {
	select {
	case <-c.catchup.wake:
		return true
	default:
		return false
	}
}

// signedResponse is a response for the client's shard whose certificate is signed by the given committee in the given epoch.
func signedResponse(t *testing.T, epoch uint64, signers []fixtureMember) *certification.CertificationResponse {
	t.Helper()
	tr := certification.TechnicalRecord{Round: 4, Epoch: epoch, Leader: "leader", StatHash: []byte{1}, FeeHash: []byte{1}}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	uc := fixtureCertificateWithTR(t, 5, epoch, 150, signers, trHash)
	cr := &certification.CertificationResponse{Partition: fixturePartition, UC: *uc, Technical: tr}
	require.NoError(t, cr.IsValid())
	return cr
}

// The attached entries are an authority update: they are appended before the certificate is looked at and independently of its status, and a
// certificate of the wrong committee advances nothing.
func TestAttachedEntriesAreAppendedBeforeAndIndependentlyOfTheCertificate(t *testing.T) {
	other := fixtureMembers(t, 4)
	for _, status := range []uint32{certification.CertStatusOK, certification.CertStatusRequestInvalid} {
		c2, h2, _, _, e2raw, _ := threeEpochs(t, fixturePartition)
		cr := signedResponse(t, 2, other[:3]) // epoch 2 certified by a committee that is not epoch 2's
		cr.Status = status
		err := c2.handleCombinedResponse(context.Background(), cr, [][]byte{e2raw})
		require.Error(t, err)
		require.Equal(t, uint64(2), tipOf(h2), "status %d: the valid entry is kept", status)
		require.Nil(t, c2.luc.Load(), "status %d: a refused certificate advances nothing", status)
		require.Equal(t, uint64(2), c2.admittedHead.Load(), "status %d: the admitted head follows the history", status)
	}
}

// An entry that does not follow the held tip only wakes the catch-up worker; the message path never fetches.
func TestAGapWakesTheWorkerAndNeverFetchesOnTheMessagePath(t *testing.T) {
	c, h, srv, _, _, e3raw := threeEpochs(t, fixturePartition)
	f := &countingFetcher{inner: &fixtureFetcher{Srv: srv}}
	c.trustBaseFetcher = f
	// the response's own certificate is of the held epoch 1 (refused: not its committee), so only the gap can wake the worker
	err := c.handleCombinedResponse(context.Background(), signedResponse(t, 1, fixtureMembers(t, 4)[:3]), [][]byte{e3raw})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrEpochNotAdmitted)
	require.Equal(t, uint64(1), tipOf(h))
	require.Zero(t, f.calls)
	require.True(t, woken(c))
}

// A certificate of an epoch the client does not hold is dropped and wakes the worker; the worker fetches the entry after the held tip from the roots and
// the same certificate then verifies.
func TestUnknownEpochIsDroppedThenCaughtUpByTheWorker(t *testing.T) {
	c, h, srv, j, _, _ := threeEpochs(t, fixturePartition)
	f := &countingFetcher{inner: &fixtureFetcher{Srv: srv}}
	c.trustBaseFetcher = f
	uc := fixtureCertificate(t, 5, 2, 150, j[:3])
	partition := fixturePartition

	err := c.authn.beginIntake(context.Background()).verifyUC(uc, partition, types.ShardID{})
	require.ErrorIs(t, err, ErrEpochNotAdmitted)
	require.Zero(t, f.calls)
	require.Equal(t, uint64(1), tipOf(h))

	c.catchup.runOnce(context.Background())
	require.Positive(t, f.calls)
	require.Equal(t, uint64(3), tipOf(h), "the worker admits what the root holds, one authenticated entry at a time")
	require.Equal(t, uint64(3), c.admittedHead.Load())
	require.NoError(t, c.authn.beginIntake(context.Background()).verifyUC(uc, partition, types.ShardID{}))
}

// A response for another shard is refused before its certificate is looked at, so it never wakes the worker.
func TestWrongShardNeverWakesTheWorker(t *testing.T) {
	c, h, _, j, _, _ := threeEpochs(t, fixturePartition+1)
	cr := signedResponse(t, 2, j[:3])
	require.ErrorContains(t, c.handleCertificationResponse(context.Background(), cr), "wrong shard")
	require.Equal(t, uint64(1), tipOf(h))
	require.False(t, woken(c))
}

// A restart with a fresh store: the last certificate's epoch is not held and cannot be fetched, so the handshake greets the newest held committee
// instead of failing, and that committee is admitted so its reply is accepted.
func TestRestartWithAFreshStoreGreetsAndAdmitsTheNewestHeldCommittee(t *testing.T) {
	c, h, _, j, _, _ := threeEpochs(t, fixturePartition)
	c.luc.Store(fixtureCertificate(t, 5, 2, 150, j[:3])) // epoch 2, not held

	tb, err := c.handshakeAuthority(context.Background(), 2)
	require.NoError(t, err)
	g, err := h.Committee(1)
	require.NoError(t, err)
	require.Equal(t, g.GetEpoch(), tb.GetEpoch())
	require.True(t, woken(c))

	ids, err := rootNodesIDSlice(tb)
	require.NoError(t, err)
	c.members.live.Store(2) // the live epoch is the stored certificate's, which this store does not hold
	require.NoError(t, c.members.Refresh(context.Background()))
	for _, id := range ids {
		require.True(t, c.members.Contains(id), "genesis committee member %s must be admitted", id)
	}
	// without the fallback the live epoch's absence would leave the set empty
	c.members.headFallback = false
	require.Error(t, c.members.Refresh(context.Background()))
}

// The held history is the whole authority source in UTB mode: version 1 trust bases are not consulted.
func TestUTBModeNeverConsultsVersion1TrustBases(t *testing.T) {
	c, _, _, _, _, _ := threeEpochs(t, fixturePartition)
	_, err := c.trustBaseStore.GetByEpoch(context.Background(), 1)
	require.Error(t, err)
	_, err = utbIntake{c}.GetByEpochLocal(context.Background(), 9)
	require.ErrorIs(t, err, interfaces.ErrTrustBaseNotFound)
}

var _ = errors.New

// Certificates are judged by the shared authenticator under the held entry of the seal's own epoch: its strict weighted quorum, the network, the
// epoch's start and, once the successor is held, its retirement.
func TestAuthenticatorUnderTheHeldHistory(t *testing.T) {
	const net types.NetworkID = 5
	k, j := fixtureMembers(t, 4), fixtureMembers(t, 4)
	outsider := fixtureMembers(t, 1)[0]
	g := fixtureEntryOf(t, net, 1, 1, k, nil, nil)
	e2 := fixtureEntryOf(t, net, 2, 100, j, g, k[:3])
	graw, err := g.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	h := openHistory(t, [][]byte{graw}, gid)
	a := newHistoryAuthenticator(net, utbAuthority{h})
	verify := func(uc *types.UnicityCertificate) error {
		return a.beginIntake(context.Background()).verifyUC(uc, fixturePartition, types.ShardID{})
	}

	require.NoError(t, verify(fixtureCertificate(t, net, 1, 50, k[:3])))
	require.NoError(t, verify(fixtureCertificate(t, net, 1, 150, k[:3]))) // the newest held epoch accepts rounds >= its start until its successor is held
	require.ErrorIs(t, verify(fixtureCertificate(t, net, 2, 150, j[:3])), ErrEpochNotAdmitted)

	raw2, err := e2.MarshalCBOR()
	require.NoError(t, err)
	added, gap, err := h.Ingest(context.Background(), [][]byte{raw2})
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 1, added)

	require.NoError(t, verify(fixtureCertificate(t, net, 1, 50, k[:3])))  // a historical certificate verifies with its own committee
	require.NoError(t, verify(fixtureCertificate(t, net, 2, 150, j[:3]))) // the new epoch with the new committee
	require.NoError(t, verify(fixtureCertificate(t, net, 2, 100, j)))     // at the new start, all signers
	cases := []struct {
		name string
		uc   *types.UnicityCertificate
		want string
	}{
		{"the retired committee after its successor started", fixtureCertificate(t, net, 1, 100, k[:3]), "retired"},
		{"the old committee signing the new epoch", fixtureCertificate(t, net, 2, 150, k[:3]), "is not a member"},
		{"before the epoch's start", fixtureCertificate(t, net, 2, 99, j[:3]), "before the start of epoch 2"},
		{"below the weighted threshold", fixtureCertificate(t, net, 2, 150, j[:2]), "quorum not reached"},
		{"an unknown extra signer", fixtureCertificate(t, net, 2, 150, append(j[:3:3], outsider)), "is not a member"},
		{"another network", fixtureCertificate(t, net+1, 2, 150, j[:3]), "network"},
	}
	for _, c := range cases {
		err := verify(c.uc)
		require.Error(t, err, c.name)
		require.NotErrorIs(t, err, ErrEpochNotAdmitted, c.name)
		require.ErrorContains(t, err, c.want, c.name)
	}
	require.ErrorIs(t, verify(fixtureCertificate(t, net, 3, 500, j[:3])), ErrEpochNotAdmitted)

	uc := fixtureCertificate(t, net, 2, 150, j[:3]) // a broken signature among valid ones fails the whole check
	for id, sig := range uc.UnicitySeal.Signatures {
		bad := append(bfthex.Bytes(nil), sig...)
		bad[3] ^= 1
		uc.UnicitySeal.Signatures[id] = bad
		break
	}
	require.Error(t, verify(uc))
}

// The routing targets gain the newest held committee only when it is newer than the certificate's epoch, and never lose the certificate's own.
func TestRoutingAddsTheNewestHeldCommitteeOnlyWhenNewer(t *testing.T) {
	c, h, _, _, e2raw, e3raw := threeEpochs(t, fixturePartition)
	pick := randomPicker(16)
	g, err := h.Committee(1)
	require.NoError(t, err)
	genesisIDs, err := rootNodesIDSlice(g)
	require.NoError(t, err)

	require.Equal(t, genesisIDs, c.withNewestCommittee(genesisIDs, 1, pick), "nothing newer is held")
	_, _, err = h.Ingest(context.Background(), [][]byte{e2raw, e3raw})
	require.NoError(t, err)
	e3, err := h.Committee(3)
	require.NoError(t, err)
	newest, err := rootNodesIDSlice(e3)
	require.NoError(t, err)
	got := c.withNewestCommittee(genesisIDs, 1, pick)
	require.Subset(t, got, genesisIDs)
	require.Subset(t, got, newest)
	require.Equal(t, genesisIDs, c.withNewestCommittee(genesisIDs, 3, pick), "the certificate's epoch is the newest")
	require.Equal(t, genesisIDs, c.withNewestCommittee(genesisIDs, 7, pick), "an epoch beyond the tip adds nothing")
}

// The memo of authenticated seals is keyed by the authority's identity: the EntryID for version 2 (so another valid witness of the same entry is the same
// authority) and the hash for version 1.
func TestAuthorityDigestIdentifiesTheEntryNotItsWitness(t *testing.T) {
	const net types.NetworkID = 5
	k, j := fixtureMembers(t, 4), fixtureMembers(t, 4)
	g := fixtureEntryOf(t, net, 1, 1, k, nil, nil)
	e2 := fixtureEntryOf(t, net, 2, 100, j, g, k[:3])
	e2all := fixtureEntryOf(t, net, 2, 100, j, g, k) // same unsigned entry, another valid signature subset
	d2, err := authorityDigest(e2)
	require.NoError(t, err)
	d2all, err := authorityDigest(e2all)
	require.NoError(t, err)
	require.Equal(t, d2, d2all)
	id2, err := e2.EntryID()
	require.NoError(t, err)
	require.Equal(t, [32]byte(id2), d2)
	dg, err := authorityDigest(g)
	require.NoError(t, err)
	require.NotEqual(t, d2, dg)
	_, err = authorityDigest(nil)
	require.Error(t, err)
}

// An attachment which adds nothing (every entry already held) is not silent: it is logged at DEBUG, so the evidence can show it was consumed. A new entry is
// logged at INFO as before and does not produce the DEBUG line.
func TestAnAttachmentWhichAddsNothingIsLoggedAtDebug(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "agg.log")
	lg, err := logger.NewWithConfig(logger.LogConfig{Level: "debug", Format: "json", Output: "stdout", EnableJSON: true, FilePath: logFile})
	require.NoError(t, err)
	c, h, _, _, e2raw, _ := threeEpochs(t, fixturePartition)
	c.logger = lg
	cr := signedResponse(t, 1, fixtureMembers(t, 4)[:3])
	_ = c.handleCombinedResponse(context.Background(), cr, [][]byte{e2raw}) // new: appended
	require.Equal(t, uint64(2), tipOf(h))
	_ = c.handleCombinedResponse(context.Background(), cr, [][]byte{e2raw}) // the same entry again: nothing added
	raw, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(raw), "trust-base entries appended from certification response"), string(raw))
	require.Equal(t, 1, strings.Count(string(raw), "trust-base update already held"), string(raw))
	require.NotContains(t, string(raw), "trust-base gap in certification response")
}

func tipOf(h UTBHistory) uint64 { e, _ := h.Tip(); return e }

// rawSource serves a chain of raw entries the way a root's store does (gettrustbase.Source).
type rawSource struct {
	raws    [][]byte
	entries []*types.RootTrustBaseV2
}

func (s rawSource) Tip() utbstore.Tip {
	id, _ := s.entries[len(s.entries)-1].EntryID()
	return utbstore.Tip{Epoch: uint64(len(s.entries)), EntryID: id}
}
func (s rawSource) GenesisEpoch() uint64 { return 1 }
func (s rawSource) Entry(epoch uint64) (*types.RootTrustBaseV2, error) {
	if epoch < 1 || epoch > uint64(len(s.entries)) {
		return nil, utbstore.ErrNotFound
	}
	return s.entries[epoch-1], nil
}
func (s rawSource) Range(from, to uint64, maxEntries, maxBytes int) ([][]byte, uint64, bool, error) {
	if from < 1 {
		from = 1
	}
	if to > uint64(len(s.entries)) {
		to = uint64(len(s.entries))
	}
	if from > to {
		return nil, 0, false, utbstore.ErrNotFound
	}
	var out [][]byte
	used := 0
	for e := from; e <= to; e++ {
		b := s.raws[e-1]
		if len(out) >= maxEntries || used+len(b) > maxBytes {
			return out, e, true, nil
		}
		out, used = append(out, b), used+len(b)
	}
	return out, 0, false, nil
}

// openHistory opens a history over a bundle of the given raw entries and a fresh in-memory store.
func openHistory(t *testing.T, raws [][]byte, pin [types.TrustBaseV2IDLen]byte) *utb.History {
	t.Helper()
	data, err := types.EncodeTrustBaseBundle(raws)
	require.NoError(t, err)
	h, err := utb.Open(context.Background(), utb.LoadConfig{Path: utbtest.WriteFile(t, "b.cbor", data), Pin: pin, Network: 5}, utbtest.NewMemStore())
	require.NoError(t, err)
	return h
}

// A quiet shard receives no attachments: the poll alone wakes the one catch-up worker, which fetches from the held tip.
func TestThePollWakesTheWorkerOnAQuietShard(t *testing.T) {
	c, h, srv, _, _, _ := threeEpochs(t, fixturePartition)
	f := &countingFetcher{inner: &fixtureFetcher{Srv: srv}}
	c.trustBaseFetcher = f
	c.ensureIntake()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.catchup.Run(ctx)
	go c.runUTBPoll(ctx, 20*time.Millisecond)
	require.Eventually(t, func() bool { return tipOf(h) == 3 }, 5*time.Second, 10*time.Millisecond, "no message ever arrived")
	require.Equal(t, uint64(3), c.admittedHead.Load())
}

// The poll interval is 30s by default and varies by at most 20% either way; it is never zero and never in lockstep.
func TestPollDelayIsJitteredWithinTwentyPercent(t *testing.T) {
	require.Equal(t, 24*time.Second, pollDelay(DefaultUTBPollInterval, 0))
	require.Equal(t, 30*time.Second, pollDelay(DefaultUTBPollInterval, 0.5))
	require.InDelta(t, float64(36*time.Second), float64(pollDelay(DefaultUTBPollInterval, 0.999999)), float64(time.Millisecond))
}
