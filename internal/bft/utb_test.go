package bft

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	bfthex "github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/aggregator-go/internal/config"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/storage/interfaces"
	"github.com/unicitynetwork/aggregator-go/internal/utb"
	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

// threeEpochs is a client holding only the genesis of a three-epoch chain and an in-process root holding all three entries.
func threeEpochs(t *testing.T, partition types.PartitionID) (*BFTClientImpl, *utb.History, *gettrustbase.Server, []utbtest.Member, []byte, []byte) {
	t.Helper()
	const net types.NetworkID = 5
	k, j, l := utbtest.NewMembers(t, 4), utbtest.NewMembers(t, 4), utbtest.NewMembers(t, 4)
	g := utbtest.Entry(t, net, 1, 1, k, nil, nil)
	e2 := utbtest.Entry(t, net, 2, 100, j, g, k[:3])
	e3 := utbtest.Entry(t, net, 3, 200, l, e2, j[:3])
	graw, err := g.MarshalCBOR()
	require.NoError(t, err)
	e2raw, err := e2.MarshalCBOR()
	require.NoError(t, err)
	e3raw, err := e3.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	pin := "0x" + hex.EncodeToString(gid[:])
	dir := t.TempDir()
	genesis := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesis, graw, 0o600))
	bundle, err := gettrustbase.EncodeBundle([][]byte{graw, e2raw, e3raw})
	require.NoError(t, err)
	bundleFile := filepath.Join(dir, "root.cbor")
	require.NoError(t, os.WriteFile(bundleFile, bundle, 0o600))

	h, err := utb.Open("", genesis, pin, filepath.Join(dir, "client.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	root, err := utb.Open(bundleFile, "", pin, filepath.Join(dir, "root.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	srv, err := gettrustbase.NewServer(root.Source(), gettrustbase.Config{})
	require.NoError(t, err)

	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	c, err := NewBFTClient(context.Background(), &config.BFTConfig{ShardConf: &types.PartitionDescriptionRecord{NetworkID: net, PartitionID: partition}}, nil, h, nil, log, nil)
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
func signedResponse(t *testing.T, epoch uint64, signers []utbtest.Member) *certification.CertificationResponse {
	t.Helper()
	tr := certification.TechnicalRecord{Round: 4, Epoch: epoch, Leader: "leader", StatHash: []byte{1}, FeeHash: []byte{1}}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	uc := utbtest.CertificateWithTR(t, 5, epoch, 150, signers, trHash)
	cr := &certification.CertificationResponse{Partition: utbtest.Partition, UC: *uc, Technical: tr}
	require.NoError(t, cr.IsValid())
	return cr
}

// The attached entries are an authority update: they are appended before the certificate is looked at and independently of its status, and a
// certificate of the wrong committee advances nothing.
func TestAttachedEntriesAreAppendedBeforeAndIndependentlyOfTheCertificate(t *testing.T) {
	other := utbtest.NewMembers(t, 4)
	for _, status := range []uint32{certification.CertStatusOK, certification.CertStatusRequestInvalid} {
		c2, h2, _, _, e2raw, _ := threeEpochs(t, utbtest.Partition)
		cr := signedResponse(t, 2, other[:3]) // epoch 2 certified by a committee that is not epoch 2's
		cr.Status = status
		err := c2.handleCombinedResponse(context.Background(), cr, [][]byte{e2raw})
		require.Error(t, err)
		require.Equal(t, uint64(2), h2.Tip().Epoch, "status %d: the valid entry is kept", status)
		require.Nil(t, c2.luc.Load(), "status %d: a refused certificate advances nothing", status)
		require.Equal(t, uint64(2), c2.admittedHead.Load(), "status %d: the admitted head follows the history", status)
	}
}

// An entry that does not follow the held tip only wakes the catch-up worker; the message path never fetches.
func TestAGapWakesTheWorkerAndNeverFetchesOnTheMessagePath(t *testing.T) {
	c, h, srv, _, _, e3raw := threeEpochs(t, utbtest.Partition)
	f := &countingFetcher{inner: &utbtest.Fetcher{Srv: srv}}
	c.trustBaseFetcher = f
	// the response's own certificate is of the held epoch 1 (refused: not its committee), so only the gap can wake the worker
	err := c.handleCombinedResponse(context.Background(), signedResponse(t, 1, utbtest.NewMembers(t, 4)[:3]), [][]byte{e3raw})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrEpochNotAdmitted)
	require.Equal(t, uint64(1), h.Tip().Epoch)
	require.Zero(t, f.calls)
	require.True(t, woken(c))
}

// A certificate of an epoch the client does not hold is dropped and wakes the worker; the worker fetches the entry after the held tip from the roots and
// the same certificate then verifies.
func TestUnknownEpochIsDroppedThenCaughtUpByTheWorker(t *testing.T) {
	c, h, srv, j, _, _ := threeEpochs(t, utbtest.Partition)
	f := &countingFetcher{inner: &utbtest.Fetcher{Srv: srv}}
	c.trustBaseFetcher = f
	uc := utbtest.Certificate(t, 5, 2, 150, j[:3])
	partition := utbtest.Partition
	c.authn.withShardConfHash(uc.ShardConfHash) // the fixture certificate's own configuration

	err := c.authn.beginIntake(context.Background()).verifyUC(uc, partition, types.ShardID{})
	require.ErrorIs(t, err, ErrEpochNotAdmitted)
	require.Zero(t, f.calls)
	require.Equal(t, uint64(1), h.Tip().Epoch)

	c.catchup.runOnce(context.Background())
	require.Positive(t, f.calls)
	require.Equal(t, uint64(3), h.Tip().Epoch, "the worker admits what the root holds, one authenticated entry at a time")
	require.Equal(t, uint64(3), c.admittedHead.Load())
	require.NoError(t, c.authn.beginIntake(context.Background()).verifyUC(uc, partition, types.ShardID{}))
}

// A response for another shard is refused before its certificate is looked at, so it never wakes the worker.
func TestWrongShardNeverWakesTheWorker(t *testing.T) {
	c, h, _, j, _, _ := threeEpochs(t, utbtest.Partition+1)
	cr := signedResponse(t, 2, j[:3])
	require.ErrorContains(t, c.handleCertificationResponse(context.Background(), cr), "wrong shard")
	require.Equal(t, uint64(1), h.Tip().Epoch)
	require.False(t, woken(c))
}

// A restart with a fresh store: the last certificate's epoch is not held and cannot be fetched, so the handshake greets the newest held committee
// instead of failing, and that committee is admitted so its reply is accepted.
func TestRestartWithAFreshStoreGreetsAndAdmitsTheNewestHeldCommittee(t *testing.T) {
	c, h, _, j, _, _ := threeEpochs(t, utbtest.Partition)
	c.luc.Store(utbtest.Certificate(t, 5, 2, 150, j[:3])) // epoch 2, not held

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
	c, _, _, _, _, _ := threeEpochs(t, utbtest.Partition)
	_, err := c.utb.GetByEpoch(context.Background(), 1)
	require.Error(t, err)
	_, err = utbIntake{c}.GetByEpochLocal(context.Background(), 9)
	require.ErrorIs(t, err, interfaces.ErrTrustBaseNotFound)
}

var _ = errors.New

// Certificates are judged by the shared authenticator under the held entry of the seal's own epoch: its strict weighted quorum, the network, the
// epoch's start and, once the successor is held, its retirement.
func TestAuthenticatorUnderTheHeldHistory(t *testing.T) {
	const net types.NetworkID = 5
	k, j := utbtest.NewMembers(t, 4), utbtest.NewMembers(t, 4)
	outsider := utbtest.NewMembers(t, 1)[0]
	g := utbtest.Entry(t, net, 1, 1, k, nil, nil)
	e2 := utbtest.Entry(t, net, 2, 100, j, g, k[:3])
	graw, err := g.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	dir := t.TempDir()
	genesis := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesis, graw, 0o600))
	h, err := utb.Open("", genesis, "0x"+hex.EncodeToString(gid[:]), filepath.Join(dir, "utb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	a := newHistoryAuthenticator(net, utbAuthority{h})
	verify := func(uc *types.UnicityCertificate) error {
		return a.beginIntake(context.Background()).verifyUC(uc, utbtest.Partition, types.ShardID{})
	}

	require.NoError(t, verify(utbtest.Certificate(t, net, 1, 50, k[:3])))
	require.NoError(t, verify(utbtest.Certificate(t, net, 1, 150, k[:3]))) // the newest held epoch accepts rounds >= its start until its successor is held
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 2, 150, j[:3])), ErrEpochNotAdmitted)

	raw2, err := e2.MarshalCBOR()
	require.NoError(t, err)
	added, gap, err := h.Ingest([][]byte{raw2})
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 1, added)

	require.NoError(t, verify(utbtest.Certificate(t, net, 1, 50, k[:3])))  // a historical certificate verifies with its own committee
	require.NoError(t, verify(utbtest.Certificate(t, net, 2, 150, j[:3]))) // the new epoch with the new committee
	require.NoError(t, verify(utbtest.Certificate(t, net, 2, 100, j)))     // at the new start, all signers
	cases := []struct {
		name string
		uc   *types.UnicityCertificate
		want string
	}{
		{"the retired committee after its successor started", utbtest.Certificate(t, net, 1, 100, k[:3]), "retired"},
		{"the old committee signing the new epoch", utbtest.Certificate(t, net, 2, 150, k[:3]), "is not a member"},
		{"before the epoch's start", utbtest.Certificate(t, net, 2, 99, j[:3]), "before the start of epoch 2"},
		{"below the weighted threshold", utbtest.Certificate(t, net, 2, 150, j[:2]), "quorum not reached"},
		{"an unknown extra signer", utbtest.Certificate(t, net, 2, 150, append(j[:3:3], outsider)), "is not a member"},
		{"another network", utbtest.Certificate(t, net+1, 2, 150, j[:3]), "network"},
	}
	for _, c := range cases {
		err := verify(c.uc)
		require.Error(t, err, c.name)
		require.NotErrorIs(t, err, ErrEpochNotAdmitted, c.name)
		require.ErrorContains(t, err, c.want, c.name)
	}
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 3, 500, j[:3])), ErrEpochNotAdmitted)

	uc := utbtest.Certificate(t, net, 2, 150, j[:3]) // a broken signature among valid ones fails the whole check
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
	c, h, _, _, e2raw, e3raw := threeEpochs(t, utbtest.Partition)
	pick := randomPicker(16)
	g, err := h.Committee(1)
	require.NoError(t, err)
	genesisIDs, err := rootNodesIDSlice(g)
	require.NoError(t, err)

	require.Equal(t, genesisIDs, c.withNewestCommittee(genesisIDs, 1, pick), "nothing newer is held")
	_, _, err = h.Ingest([][]byte{e2raw, e3raw})
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
	k, j := utbtest.NewMembers(t, 4), utbtest.NewMembers(t, 4)
	g := utbtest.Entry(t, net, 1, 1, k, nil, nil)
	e2 := utbtest.Entry(t, net, 2, 100, j, g, k[:3])
	e2all := utbtest.Entry(t, net, 2, 100, j, g, k) // same unsigned entry, another valid signature subset
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
	c, h, _, _, e2raw, _ := threeEpochs(t, utbtest.Partition)
	c.logger = lg
	cr := signedResponse(t, 1, utbtest.NewMembers(t, 4)[:3])
	_ = c.handleCombinedResponse(context.Background(), cr, [][]byte{e2raw}) // new: appended
	require.Equal(t, uint64(2), h.Tip().Epoch)
	_ = c.handleCombinedResponse(context.Background(), cr, [][]byte{e2raw}) // the same entry again: nothing added
	raw, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(raw), "trust-base entries appended from certification response"), string(raw))
	require.Equal(t, 1, strings.Count(string(raw), "trust-base update already held"), string(raw))
	require.NotContains(t, string(raw), "trust-base gap in certification response")
}
