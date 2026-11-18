package bft

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/proofmaterial"
	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// A continuing aggregator across live shard configuration changes (validator-registry kind 6 ReplaceAggregatorValidators, which changes the
// validators, and kind 8 UpdatePartition, which changes parameters): the root certifies the successor's hash in every certificate of the new
// shard epoch, and the client must follow it from the root seal while old certificates keep verifying against the configuration they were
// certified under.

type confServer struct {
	byEpoch map[uint64]*types.PartitionDescriptionRecord
	calls   []uint64
	fail    error
}

func (s *confServer) ShardConfig(_ context.Context, _ types.PartitionID, epoch uint64) (*types.PartitionDescriptionRecord, error) {
	s.calls = append(s.calls, epoch)
	if s.fail != nil {
		return nil, s.fail
	}
	return s.byEpoch[epoch], nil
}

func confHashOf(t *testing.T, p *types.PartitionDescriptionRecord) []byte {
	h, err := p.Hash(crypto.SHA256)
	require.NoError(t, err)
	return h
}

// followFixture holds the client at shard epoch 0 and the root's served successors: epoch 1 replaces the validators (kind 6), epoch 2 changes
// a timeout (kind 8).
type followFixture struct {
	c          *BFTClientImpl
	signers    []utbtest.Member
	srv        *confServer
	pdr0, pdr1 *types.PartitionDescriptionRecord
	pdr2       *types.PartitionDescriptionRecord
	topo       *proofmaterial.StaticTopology
	h0, h1, h2 []byte
	rootRound  uint64
	trHash     []byte
}

func newFollowFixture(t *testing.T) *followFixture {
	c, _, srv, j, _, _ := threeEpochs(t, utbtest.Partition)
	c.trustBaseFetcher = &utbtest.Fetcher{Srv: srv}
	c.catchup.runOnce(context.Background())
	node := func(id string) *types.NodeInfo {
		return &types.NodeInfo{NodeID: id, SigKey: []byte{2, byte(len(id))}, Stake: 1}
	}
	f := &followFixture{c: c, signers: j[:3], rootRound: 150}
	f.pdr0 = &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: utbtest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1, Validators: []*types.NodeInfo{node("a1")}}
	p1 := *f.pdr0
	p1.Epoch, p1.EpochStart, p1.Validators = 1, 100, []*types.NodeInfo{node("a1"), node("a22")}
	f.pdr1 = &p1
	p2 := p1
	p2.Epoch, p2.EpochStart, p2.T2Timeout = 2, 200, 7*time.Second
	f.pdr2 = &p2
	f.h0, f.h1, f.h2 = confHashOf(t, f.pdr0), confHashOf(t, f.pdr1), confHashOf(t, f.pdr2)
	require.NotEqual(t, f.h0, f.h1)
	require.NotEqual(t, f.h1, f.h2)
	f.srv = &confServer{byEpoch: map[uint64]*types.PartitionDescriptionRecord{1: f.pdr1, 2: f.pdr2}}
	f.c.conf.ShardConf = f.pdr0
	f.c.authn.withShardConfHash(f.h0)
	f.c.SetShardConfSource(f.srv)
	tr := sha256.Sum256([]byte("technical record"))
	f.trHash = tr[:]
	return f
}

func (f *followFixture) cert(t *testing.T, conf []byte) *types.UnicityCertificate {
	f.rootRound++
	return utbtest.CertificateWithConf(t, 5, 2, f.rootRound, f.signers, f.trHash, conf)
}

func (f *followFixture) verify(uc *types.UnicityCertificate) error {
	return f.c.authn.beginIntake(context.Background()).verifyUC(uc, utbtest.Partition, types.ShardID{})
}

func TestAContinuingAggregatorFollowsAKind6AndAKind8Boundary(t *testing.T) {
	f := newFollowFixture(t)
	old := f.cert(t, f.h0)
	require.NoError(t, f.verify(old), "the configuration it started with")
	require.Empty(t, f.srv.calls, "a known configuration needs no fetch")

	// kind 6: the first certificate of shard epoch 1 commits to the successor
	first := f.cert(t, f.h1)
	require.NoError(t, f.verify(first))
	require.Equal(t, []uint64{1}, f.srv.calls)
	require.Equal(t, f.h1, f.c.authn.currentConfHash())
	require.NoError(t, f.verify(f.cert(t, f.h1)), "and the next ones, without another fetch")
	require.Equal(t, []uint64{1}, f.srv.calls)

	// historical certificates keep verifying against the configuration that applied to them
	require.NoError(t, f.verify(old), "a certificate of the old validator set")
	require.NoError(t, f.verify(first))

	// kind 8: the next change follows the same way
	require.NoError(t, f.verify(f.cert(t, f.h2)))
	require.Equal(t, []uint64{1, 2}, f.srv.calls)
	require.Equal(t, f.h2, f.c.authn.currentConfHash())
	require.NoError(t, f.verify(old))
	require.NoError(t, f.verify(first))

	// a certificate of a configuration that is none of the shard's is refused, and never adopted
	foreign := sha256.Sum256([]byte("another configuration"))
	require.ErrorIs(t, f.verify(f.cert(t, foreign[:])), ErrShardConfUnknown)
	require.Equal(t, f.h2, f.c.authn.currentConfHash())
}

func TestAClientCatchesUpAcrossSeveralChangesInOneStep(t *testing.T) {
	f := newFollowFixture(t)
	require.NoError(t, f.verify(f.cert(t, f.h2)), "down across both changes: the first certificate it sees is of epoch 2")
	require.Equal(t, []uint64{1, 2}, f.srv.calls, "the epochs are walked in order")
	require.NoError(t, f.verify(f.cert(t, f.h0)), "the configuration it started with")
	// the epoch it skipped was never sealed to it: only the configurations it started with or adopted from a sealed hash are held
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfUnknown)
}

func TestASuccessorIsOnlyAdoptedFromAnAuthenticatedCertificate(t *testing.T) {
	f := newFollowFixture(t)
	// a certificate whose seal is not the quorum's (one signer short) never adopts a configuration
	uc := utbtest.CertificateWithConf(t, 5, 2, 151, f.signers[:1], f.trHash, f.h1)
	require.Error(t, f.verify(uc))
	require.Empty(t, f.srv.calls, "the configuration is fetched only after the seal verified")
	require.Equal(t, f.h0, f.c.authn.currentConfHash())

	// a certificate of an epoch the client has not admitted yet is dropped (retryable), not adopted
	late := utbtest.CertificateWithConf(t, 5, 9, 900, f.signers, f.trHash, f.h1)
	require.ErrorIs(t, f.verify(late), ErrEpochNotAdmitted)
	require.Equal(t, f.h0, f.c.authn.currentConfHash())
}

func TestAServedConfigurationMustHashToTheSealedValue(t *testing.T) {
	f := newFollowFixture(t)
	// the root serves a configuration other than the sealed one for epoch 1, and nothing for 2..: not adopted
	liar := *f.pdr1
	liar.T2Timeout = time.Hour
	f.srv.byEpoch = map[uint64]*types.PartitionDescriptionRecord{1: &liar}
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfUnknown)
	require.Equal(t, f.h0, f.c.authn.currentConfHash())

	// a configuration of another shard, or of a wrong epoch, is refused even if it hashed to the sealed value
	other := *f.pdr1
	other.PartitionID++
	f.srv.byEpoch = map[uint64]*types.PartitionDescriptionRecord{1: &other}
	require.ErrorIs(t, f.verify(f.cert(t, confHashOf(t, &other))), ErrShardConfUnknown)
	wrongEpoch := *f.pdr1
	wrongEpoch.Epoch = 5
	f.srv.byEpoch = map[uint64]*types.PartitionDescriptionRecord{1: &wrongEpoch}
	require.ErrorIs(t, f.verify(f.cert(t, confHashOf(t, &wrongEpoch))), ErrShardConfUnknown)

	// an unreachable root fails closed, and a later retry succeeds
	f.srv.fail = errors.New("connection refused")
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfUnknown)
	f.srv.fail = nil
	f.srv.byEpoch = map[uint64]*types.PartitionDescriptionRecord{1: f.pdr1}
	require.NoError(t, f.verify(f.cert(t, f.h1)))
}

func TestWithoutASourceTheClientKeepsItsStartupConfiguration(t *testing.T) {
	f := newFollowFixture(t)
	f.c.authn.withShardConfHash(f.h0) // no follower
	err := f.verify(f.cert(t, f.h1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid shard configuration hash")
}

func TestTheConsolidationTopologyPinFollowsTheShardConfiguration(t *testing.T) {
	f := newFollowFixture(t)
	other := sha256.Sum256([]byte("another shard"))
	topo, err := proofmaterial.NewStaticTopology(types.ShardingScheme{}, map[string][]byte{types.ShardID{}.Key(): f.h0})
	require.NoError(t, err)
	f.c.proofTopology = topo
	require.NoError(t, f.verify(f.cert(t, f.h1)))
	got, ok := topo.Topology(api.AggregationPartitionID)
	require.True(t, ok)
	require.Equal(t, f.h1, got.ShardConfHashes[types.ShardID{}.Key()], "the pin followed the adopted configuration")
	// the pin of an aggregation partition's shard moves only while it is exactly the configuration it followed
	require.False(t, topo.Follow(types.ShardID{}, f.h0, f.h1), "already moved")
	require.True(t, topo.Follow(types.ShardID{}, f.h1, f.h2))
	require.False(t, topo.Follow(types.ShardID{}, other[:], f.h0), "a pin the operator set to anything else stays")
}
