package bft

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/models"
	"github.com/unicitynetwork/aggregator-go/internal/proofpub"
	"github.com/unicitynetwork/aggregator-go/internal/proofview"
	"github.com/unicitynetwork/aggregator-go/internal/smt"
	smtbackend "github.com/unicitynetwork/aggregator-go/internal/smt/backend"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/proofmaterial"
	"github.com/unicitynetwork/aggregator-go/internal/proofmaterial/prooftest"
	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

// A continuing aggregator across live shard configuration changes (validator-registry kind 6 ReplaceAggregatorValidators, which changes the
// validators, and kind 8 UpdatePartition, which changes parameters): the root certifies the successor's hash in every certificate of the new
// shard epoch. The client resolves it off the message loop, keeps verifying historical certificates against the configuration they were
// certified under, publishes only on accepted sequence progress, and resumes from an authenticated checkpoint.

type confServer struct {
	byEpoch map[string]map[uint64]*types.PartitionDescriptionRecord // shard key -> epoch
	calls   []string
	fail    error
	delay   time.Duration
}

func (s *confServer) ShardConfig(ctx context.Context, _ types.PartitionID, shard types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error) {
	s.calls = append(s.calls, shard.Key()+"@"+string(rune('0'+epoch)))
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.fail != nil {
		return nil, s.fail
	}
	return s.byEpoch[shard.Key()][epoch], nil
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
	h0, h1, h2 []byte
	rootRound  uint64
	checkpoint string
}

func newFollowFixture(t *testing.T) *followFixture {
	c, _, srv, j, _, _ := threeEpochs(t, utbtest.Partition)
	c.trustBaseFetcher = &utbtest.Fetcher{Srv: srv}
	c.catchup.runOnce(context.Background())
	node := func(id string) *types.NodeInfo {
		return &types.NodeInfo{NodeID: id, SigKey: []byte{2, byte(len(id))}, Stake: 1}
	}
	f := &followFixture{c: c, signers: j[:3], rootRound: 150, checkpoint: filepath.Join(t.TempDir(), "checkpoint.json")}
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
	whole := types.ShardID{}.Key()
	f.srv = &confServer{byEpoch: map[string]map[uint64]*types.PartitionDescriptionRecord{whole: {1: f.pdr1, 2: f.pdr2}}}
	f.c.conf.ShardConf = f.pdr0
	f.c.conf.ShardConfCheckpointFile = f.checkpoint
	f.c.authn.withShardConfHash(f.h0)
	f.c.setShardConfSource(f.srv, false)
	return f
}

func (f *followFixture) cert(t *testing.T, conf []byte) *types.UnicityCertificate {
	f.rootRound++
	tr := sha256.Sum256([]byte("technical record"))
	return utbtest.CertificateWithConf(t, 5, 2, f.rootRound, f.signers, tr[:], conf)
}

func (f *followFixture) verify(uc *types.UnicityCertificate, hints ...uint64) error {
	return f.verifyDeferred(uc, nil, hints...)
}

// verifyDeferred is verify for the response cr, which the lookup it queues keeps until it is handed back.
func (f *followFixture) verifyDeferred(uc *types.UnicityCertificate, cr any, hints ...uint64) error {
	op := f.c.authn.beginIntake(context.Background())
	op.confHints = hints
	op.deferred = cr
	return op.verifyUC(uc, utbtest.Partition, types.ShardID{})
}

// resolve runs the worker's pass once, as its loop does, and reports whether the dropped certificate was handed back.
func (f *followFixture) resolve() {
	f.c.follow.process(context.Background())
}

func TestAContinuingAggregatorFollowsAKind6AndAKind8Boundary(t *testing.T) {
	f := newFollowFixture(t)
	old := f.cert(t, f.h0)
	require.NoError(t, f.verify(old), "the configuration it started with")
	require.Empty(t, f.srv.calls, "a known configuration needs no fetch")

	// kind 6: the first certificate of shard epoch 1 is authentic but its configuration is unknown: dropped, nothing fetched inline
	first := f.cert(t, f.h1)
	require.ErrorIs(t, f.verify(first), ErrShardConfPending)
	require.Empty(t, f.srv.calls, "resolution never runs on the message loop")
	require.ErrorIs(t, f.verify(first), ErrShardConfPending, "a duplicate is coalesced")
	require.Len(t, f.c.follow.pending, 1)
	f.resolve()
	require.Equal(t, []string{types.ShardID{}.Key() + "@1"}, f.srv.calls, "directly at the epoch the input record names, no search")
	require.NoError(t, f.verify(first))
	require.Equal(t, f.h0, f.c.authn.currentConfHash(), "known is not published: only accepted sequence progress publishes")
	f.c.publishConf(first)
	require.Equal(t, f.h1, f.c.authn.currentConfHash())

	// historical certificates keep verifying against the configuration that applied to them
	require.NoError(t, f.verify(old))
	require.NoError(t, f.verify(first))

	// kind 8: the technical record's epoch names the target directly, however far the input record lags
	second := f.cert(t, f.h2)
	require.ErrorIs(t, f.verify(second, 2), ErrShardConfPending)
	f.resolve()
	require.Equal(t, types.ShardID{}.Key()+"@2", f.srv.calls[len(f.srv.calls)-1])
	require.NoError(t, f.verify(second))
	f.c.publishConf(second)
	require.Equal(t, f.h2, f.c.authn.currentConfHash())
	require.NoError(t, f.verify(old))
	require.NoError(t, f.verify(first))

	// a certificate of a configuration that is none of the shard's is never adopted
	foreign := sha256.Sum256([]byte("another configuration"))
	require.ErrorIs(t, f.verify(f.cert(t, foreign[:]), 3), ErrShardConfPending)
	f.resolve()
	require.ErrorIs(t, f.verify(f.cert(t, foreign[:]), 3), ErrShardConfPending, "still unknown")
	require.Equal(t, f.h2, f.c.authn.currentConfHash())
}

func TestAHistoricalCertificateNeverMovesThePublishedConfiguration(t *testing.T) {
	f := newFollowFixture(t)
	second := f.cert(t, f.h2)
	require.ErrorIs(t, f.verify(second, 2), ErrShardConfPending)
	f.resolve()
	f.c.publishConf(second)
	require.Equal(t, f.h2, f.c.authn.currentConfHash())
	// an intermediate configuration, resolved later from a stale certificate that the sequence checks then discard, is known but not published
	older := f.cert(t, f.h1)
	require.ErrorIs(t, f.verify(older, 1), ErrShardConfPending)
	f.resolve()
	require.NoError(t, f.verify(older))
	f.c.publishConf(older)
	require.Equal(t, f.h2, f.c.authn.currentConfHash(), "an earlier epoch never lowers the published configuration")
}

func TestAResolutionIsBackedOffCoalescedAndDoesNotBlock(t *testing.T) {
	f := newFollowFixture(t)
	now := time.Unix(1000, 0)
	f.c.follow.now = func() time.Time { return now }
	f.srv.fail = errors.New("connection refused")
	uc := f.cert(t, f.h1)
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, f.verify(uc), ErrShardConfPending)
	}
	require.Empty(t, f.srv.calls)
	f.resolve()
	require.Len(t, f.srv.calls, 1, "one attempt: a failing source stops the pass")
	f.resolve()
	f.resolve()
	require.Len(t, f.srv.calls, 1, "backed off: duplicates of the certificate cause no new attempt")
	require.ErrorIs(t, f.verify(uc), ErrShardConfPending)
	f.resolve()
	require.Len(t, f.srv.calls, 1)
	now = now.Add(2 * time.Second)
	f.resolve()
	require.Len(t, f.srv.calls, 2)
	now = now.Add(time.Hour)
	f.srv.fail = nil
	require.ErrorIs(t, f.verify(uc), ErrShardConfPending, "an obsolete lookup was reclaimed; the certificate queues it again")
	f.resolve()
	require.NoError(t, f.verify(uc), "the source recovered: the configuration is resolved")
}

func TestASlowSourceCannotStallTheResolutionBudget(t *testing.T) {
	f := newFollowFixture(t)
	f.srv.delay = time.Hour
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfPending)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	f.c.follow.process(ctx)
	require.Less(t, time.Since(start), 5*time.Second, "the lookup honors its context")
}

func TestTheResolvedCertificateIsHandedBackToTheMessageLoop(t *testing.T) {
	f := newFollowFixture(t)
	cr := &certification.CertificationResponse{Partition: utbtest.Partition}
	require.ErrorIs(t, f.verifyDeferred(f.cert(t, f.h1), cr), ErrShardConfPending)
	f.resolve()
	select {
	case got := <-f.c.reinject:
		require.Same(t, cr, got)
	default:
		t.Fatal("the dropped certificate is re-admitted once its configuration is resolved")
	}
}

// The production ordering: the worker runs concurrently and may finish the lookup at once, so the response must be registered with the lookup
// before the worker is woken. Every deferred response of many racing intakes comes back.
func TestADeferredResponseIsNeverLostToARacingWorker(t *testing.T) {
	f := newFollowFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.c.reinject = make(chan any, 1024)
	f.c.follow.deliver = f.c.redeliver
	src := &instantSource{pdr: f.pdr1}
	f.c.follow.source = src
	go f.c.follow.run(ctx)
	for i := 0; i < 200; i++ {
		// a fresh follower state each round: forget the configuration so the lookup is queued again
		f.c.follow.mu.Lock()
		delete(f.c.follow.known[types.ShardID{}.Key()], string(f.h1))
		f.c.follow.mu.Unlock()
		cr := &certification.CertificationResponse{Partition: utbtest.Partition, Status: uint32(i)}
		tr := sha256.Sum256([]byte("technical record"))
		err := f.verifyDeferred(utbtest.CertificateWithConf(t, 5, 2, 160, f.signers, tr[:], f.h1), cr)
		if err == nil {
			continue // the lookup finished before the response was registered: it verifies now, nothing is deferred
		}
		require.ErrorIs(t, err, ErrShardConfPending)
		select {
		case got := <-f.c.reinject:
			require.Same(t, cr, got)
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: the deferred response was lost", i)
		}
	}
}

type instantSource struct {
	pdr *types.PartitionDescriptionRecord
}

func (s *instantSource) ShardConfig(context.Context, types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
	return s.pdr, nil
}

// A full reinjection channel never drops a resolved response: the follower keeps it and offers it again.
func TestAResolvedResponseIsKeptWhileTheLoopIsBusy(t *testing.T) {
	f := newFollowFixture(t)
	f.c.reinject = make(chan any, 1)
	f.c.reinject <- "busy"
	cr := &certification.CertificationResponse{Partition: utbtest.Partition}
	require.ErrorIs(t, f.verifyDeferred(f.cert(t, f.h1), cr), ErrShardConfPending)
	f.resolve()
	require.Len(t, f.c.follow.ready, 1, "not taken: kept")
	require.Equal(t, "busy", <-f.c.reinject)
	f.resolve()
	require.Same(t, cr, <-f.c.reinject)
	require.Empty(t, f.c.follow.ready)
}

func TestPendingResolutionsAreReclaimedAndTheLocalShardHasPriority(t *testing.T) {
	f := newFollowFixture(t)
	now := time.Unix(1000, 0)
	fl := f.c.follow
	fl.now = func() time.Time { return now }
	left, _ := types.ShardID{}.Split()
	for i := 0; i < maxPendingConfs; i++ {
		fl.request(left, []byte{byte(i), 1}, nil, nil) // siblings that never resolve
		now = now.Add(time.Second)
	}
	require.Len(t, fl.pending, maxPendingConfs)
	fl.request(left, []byte("one more sibling"), nil, nil)
	require.Len(t, fl.pending, maxPendingConfs, "a sibling does not displace anything")
	// the local shard's current progress has priority: it evicts the oldest sibling
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfPending)
	require.Len(t, fl.pending, maxPendingConfs)

	require.NotContains(t, fl.pending, left.Key()+"/"+string([]byte{0, 1}), "the oldest sibling was reclaimed")
	require.Contains(t, fl.pending, types.ShardID{}.Key()+"/"+string(f.h1))
	// obsolete resolutions expire
	now = now.Add(confPendingTTL + time.Second)
	fl.process(context.Background())
	require.Empty(t, fl.pending, "unresolved for longer than the TTL: reclaimed")
}

func TestAFailedCheckpointSaveIsRetried(t *testing.T) {
	f := newFollowFixture(t)
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	f.c.follow.checkpoint = filepath.Join(blocker, "sub", "checkpoint.json") // its parent cannot be created
	now := time.Unix(1000, 0)
	f.c.follow.now = func() time.Time { return now }
	second := f.cert(t, f.h2)
	require.ErrorIs(t, f.verify(second, 2), ErrShardConfPending)
	f.resolve()
	f.c.publishConf(second)
	require.NotNil(t, f.c.follow.unsaved, "the failed save is remembered")
	// the obstacle goes away: the worker retries after the retry interval and persists it
	require.NoError(t, os.Remove(blocker))
	f.resolve()
	require.NotNil(t, f.c.follow.unsaved, "not before the retry interval")
	now = now.Add(checkpointRetry + time.Second)
	f.resolve()
	require.Nil(t, f.c.follow.unsaved)
	_, err := os.Stat(f.c.follow.checkpoint)
	require.NoError(t, err, "the parent directory is created")
}

func TestASuccessorIsOnlyResolvedFromAnAuthenticatedCertificate(t *testing.T) {
	f := newFollowFixture(t)
	// a certificate whose seal is not the quorum's never queues a resolution
	uc := utbtest.CertificateWithConf(t, 5, 2, 151, f.signers[:1], make([]byte, 32), f.h1)
	require.Error(t, f.verify(uc))
	require.NotErrorIs(t, f.verify(uc), ErrShardConfPending)
	require.Empty(t, f.c.follow.pending)
	// a certificate of an epoch the client has not admitted yet is dropped (retryable), not queued
	late := utbtest.CertificateWithConf(t, 5, 9, 900, f.signers, make([]byte, 32), f.h1)
	require.ErrorIs(t, f.verify(late), ErrEpochNotAdmitted)
	require.Empty(t, f.c.follow.pending)
}

func TestAServedConfigurationMustHashToTheSealedValue(t *testing.T) {
	f := newFollowFixture(t)
	whole := types.ShardID{}.Key()
	now := time.Unix(1000, 0)
	f.c.follow.now = func() time.Time { return now }
	try := func(p *types.PartitionDescriptionRecord, sealed []byte) {
		f.srv.byEpoch[whole] = map[uint64]*types.PartitionDescriptionRecord{1: p}
		require.ErrorIs(t, f.verify(f.cert(t, sealed)), ErrShardConfPending)
		now = now.Add(time.Hour)
		f.resolve()
		require.ErrorIs(t, f.verify(f.cert(t, sealed)), ErrShardConfPending, "not resolved")
		require.Equal(t, f.h0, f.c.authn.currentConfHash())
	}
	liar := *f.pdr1
	liar.T2Timeout = time.Hour
	try(&liar, f.h1) // does not hash to the sealed value
	other := *f.pdr1
	other.PartitionID++
	try(&other, confHashOf(t, &other)) // another shard's, even if it hashes to the sealed value
	wrongEpoch := *f.pdr1
	wrongEpoch.Epoch = 5
	try(&wrongEpoch, confHashOf(t, &wrongEpoch))
	f.srv.byEpoch[whole] = map[uint64]*types.PartitionDescriptionRecord{1: f.pdr1}
	now = now.Add(time.Hour)
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfPending)
	f.resolve()
	require.NoError(t, f.verify(f.cert(t, f.h1)), "the right one resolves")
}

func TestWithoutASourceTheClientKeepsItsStartupConfiguration(t *testing.T) {
	f := newFollowFixture(t)
	f.c.authn.withShardConfHash(f.h0) // no follower
	err := f.verify(f.cert(t, f.h1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid shard configuration hash")
}

func TestARestartResumesFromTheAuthenticatedCheckpoint(t *testing.T) {
	f := newFollowFixture(t)
	second := f.cert(t, f.h2)
	require.ErrorIs(t, f.verify(second, 2), ErrShardConfPending)
	f.resolve()
	f.c.publishConf(second)
	_, err := os.Stat(f.checkpoint)
	require.NoError(t, err, "the published configuration is persisted")

	// a restarted client starts from the file configuration and resumes from the checkpoint: no fetch, the live configuration verifies
	f.srv.calls = nil
	f.c.follow, f.c.reinject = nil, nil
	f.c.authn.withShardConfHash(f.h0)
	f.c.setShardConfSource(f.srv, false)
	require.Equal(t, f.h2, f.c.authn.currentConfHash())
	require.NoError(t, f.verify(f.cert(t, f.h2)))
	require.NoError(t, f.verify(f.cert(t, f.h0)), "and the file configuration")
	require.Empty(t, f.srv.calls)

	// a tampered checkpoint (a configuration its certificate does not commit to) is ignored
	raw, err := os.ReadFile(f.checkpoint)
	require.NoError(t, err)
	pdr, uc, err := loadConfCheckpoint(f.checkpoint)
	require.NoError(t, err)
	forged := *pdr
	forged.T2Timeout = time.Hour
	require.NoError(t, saveConfCheckpoint(f.checkpoint, &forged, uc))
	f.c.follow, f.c.reinject = nil, nil
	f.c.authn.withShardConfHash(f.h0)
	f.c.setShardConfSource(f.srv, false)
	require.Equal(t, f.h0, f.c.authn.currentConfHash(), "a checkpoint that does not authenticate is ignored")
	// so is one whose certificate is not the quorum's
	bad := utbtest.CertificateWithConf(t, 5, 2, 999, f.signers[:1], make([]byte, 32), f.h2)
	require.NoError(t, saveConfCheckpoint(f.checkpoint, pdr, bad))
	f.c.follow, f.c.reinject = nil, nil
	f.c.authn.withShardConfHash(f.h0)
	f.c.setShardConfSource(f.srv, false)
	require.Equal(t, f.h0, f.c.authn.currentConfHash())
	require.NoError(t, os.WriteFile(f.checkpoint, raw, 0o600))
}

// A split shard: its configuration history is its own, the source is asked for that shard, and the consolidation topology follows the
// sibling's change too: a sharded view validates across a boundary in which two of the four shards changed.
func TestASplitShardAndItsSiblingsFollowAKind6Boundary(t *testing.T) {
	root := prooftest.Hash("root-1")
	before := prooftest.New(t, 2, 7, root, 80)
	order, err := types.CanonicalShardOrder(before.Topo.Scheme)
	require.NoError(t, err)
	ours, sibling, other := order[0], order[1], order[2]
	node := func(id string) *types.NodeInfo {
		return &types.NodeInfo{NodeID: id, SigKey: []byte{2, byte(len(id))}, Stake: 1}
	}
	mk := func(shard types.ShardID, epoch uint64, ids ...string) *types.PartitionDescriptionRecord {
		p := &types.PartitionDescriptionRecord{Version: 1, NetworkID: prooftest.NetworkID, PartitionID: prooftest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
			ShardID: shard, T2Timeout: time.Second, Epoch: epoch, EpochStart: 1 + epoch*100}
		for _, id := range ids {
			p.Validators = append(p.Validators, node(id))
		}
		return p
	}
	ours0, ours1 := mk(ours, 0, "o1"), mk(ours, 1, "o1", "o2")
	sib1 := mk(sibling, 1, "s1", "s2") // the sibling changed too, in the same boundary
	ourH1, sibH1 := confHashOf(t, ours1), confHashOf(t, sib1)
	src := &confServer{byEpoch: map[string]map[uint64]*types.PartitionDescriptionRecord{ours.Key(): {1: ours1}, sibling.Key(): {1: sib1}}}
	after := prooftest.NewWithConfs(t, prooftest.Partition, 2, 8, prooftest.Hash("root-2"), 90, map[string][]byte{ours.Key(): ourH1, sibling.Key(): sibH1})
	require.Equal(t, before.Shard, after.Shard)

	rm := &stubRoundManager{}
	c, _ := newProofClient(t, rm, before)
	c.shardID = ours
	topo := c.proofTopology.(*proofmaterial.StaticTopology)
	startHash := before.Topo.ShardConfHashes[ours.Key()]
	f := newShardConfFollower(src, ours0, startHash)
	c.follow = f
	c.reinject = make(chan any, 16)
	f.deliver = c.redeliver
	c.authn.withShardConfFollower(f, startHash)
	c.followTopology()

	// the certificate of the split shard after the boundary: authentic, configuration unknown; resolved for OUR shard (not the whole partition)
	require.ErrorIs(t, c.authn.beginIntake(context.Background()).verifyUC(after.UC, prooftest.Partition, ours), ErrShardConfPending)
	cr := response(after, after.Raw)

	// FIXED pins (the default): the operator's pin is never replaced and no lookup is made for the view; it is only proof material
	c.stagePartitionView(t.Context(), cr)
	require.Zero(t, c.proofStaging.Len(), "a view that commits to another configuration than a fixed pin is not staged")
	require.Len(t, f.pending, 1, "only the certificate's own lookup is queued: a fixed pin asks for nothing")
	_, _, err = proofmaterial.ValidateView(cr.PartitionView, &cr.UC, c.authn.sealVerifier(context.Background()), topo)
	require.Error(t, err, "and a stored view fails the same rule on revalidation")

	// FOLLOWING pins: the view is deferred until the changed shards are resolved, and registered with their lookups so it is handed back
	topo.SetFollowing(map[string]bool{ours.Key(): true, sibling.Key(): true})
	c.stagePartitionView(t.Context(), cr)
	require.Zero(t, c.proofStaging.Len(), "a view with unresolved configurations is deferred")
	require.Len(t, f.pending, 2, "the sibling's configuration is queued too")
	f.process(context.Background())
	require.ElementsMatch(t, []string{ours.Key() + "@2", ours.Key() + "@1", sibling.Key() + "@2", sibling.Key() + "@1"}, src.calls,
		"each shard is asked for its own history, input record epoch + 1 first (the record's epoch here is 1)")
	require.True(t, f.isKnown(ours, ourH1))
	require.True(t, f.isKnown(sibling, sibH1))
	require.False(t, f.isKnown(other, sibH1), "a configuration of one shard is not known for another")
	select {
	case got := <-c.reinject:
		require.Same(t, cr, got, "the sidecar is retained for retry and handed back once the sibling is resolved")
	default:
		t.Fatal("the deferred view was not handed back")
	}

	// the certificate and the view now validate across the boundary, in live intake and on revalidation alike
	require.NoError(t, c.authn.beginIntake(context.Background()).verifyUC(after.UC, prooftest.Partition, ours))
	c.stagePartitionView(t.Context(), cr)
	require.Equal(t, 1, c.proofStaging.Len(), "the sharded view validates across the boundary")
	_, _, err = proofmaterial.ValidateView(cr.PartitionView, &cr.UC, c.authn.sealVerifier(context.Background()), topo)
	require.NoError(t, err, "a stored view is revalidated under the same rule")
	pins, _ := topo.Topology(prooftest.Partition)
	require.Equal(t, before.Topo.ShardConfHashes[ours.Key()], pins.ShardConfHashes[ours.Key()], "the operator's topology is not modified")

	// a shard that is not marked as following stays fixed even when its configuration is known
	topo.SetFollowing(map[string]bool{ours.Key(): true})
	_, _, err = proofmaterial.ValidateView(cr.PartitionView, &cr.UC, c.authn.sealVerifier(context.Background()), topo)
	require.Error(t, err, "the sibling's pin is fixed")

	// a view whose changed shard serves nothing that hashes to the sealed value is never staged
	c2, _ := newProofClient(t, rm, before)
	c2.shardID = ours
	topo2 := c2.proofTopology.(*proofmaterial.StaticTopology)
	topo2.SetFollowing(map[string]bool{ours.Key(): true, sibling.Key(): true})
	f2 := newShardConfFollower(&confServer{byEpoch: map[string]map[uint64]*types.PartitionDescriptionRecord{}}, ours0, startHash)
	c2.follow = f2
	c2.authn.withShardConfFollower(f2, startHash)
	c2.followTopology()
	c2.stagePartitionView(t.Context(), cr)
	f2.process(context.Background())
	c2.stagePartitionView(t.Context(), cr)
	require.Zero(t, c2.proofStaging.Len())

	// startup: a fresh follower and topology (a restarted process, whose publisher revalidates the stored view) restore what the first one
	// resolved and validate the same split view; without it the view is dropped
	cp := filepath.Join(t.TempDir(), "checkpoint.json")
	f.checkpoint = cp
	topo.SetFollowing(map[string]bool{ours.Key(): true, sibling.Key(): true})
	c.noteViewConfigs(cr) // the certificate was accepted by the sequence check
	f.saveNeeded()
	c3, _ := newProofClient(t, rm, before)
	topo3 := c3.proofTopology.(*proofmaterial.StaticTopology)
	topo3.SetFollowing(map[string]bool{ours.Key(): true, sibling.Key(): true})
	f3 := newShardConfFollower(&confServer{byEpoch: map[string]map[uint64]*types.PartitionDescriptionRecord{}}, ours0, startHash)
	c3.follow = f3
	c3.followTopology()
	_, _, err = proofmaterial.ValidateView(cr.PartitionView, &cr.UC, c3.authn.sealVerifier(context.Background()), topo3)
	require.Error(t, err, "a fresh process knows nothing yet")
	f3.restoreKnown(cp)
	_, _, err = proofmaterial.ValidateView(cr.PartitionView, &cr.UC, c3.authn.sealVerifier(context.Background()), topo3)
	require.NoError(t, err, "restored: the publisher at startup keeps the accepted split view")
}

func TestRegisteredResponsesAreNeverSilentlyDropped(t *testing.T) {
	f := newFollowFixture(t)
	mkResp := func(round uint64, view []byte) *certification.CertificationResponse {
		uc := utbtest.CertificateWithConf(t, 5, 2, round, f.signers, make([]byte, 32), f.h1)
		return &certification.CertificationResponse{Partition: utbtest.Partition, UC: *uc, PartitionView: view}
	}
	var first []*certification.CertificationResponse
	for i := 0; i < maxConfWaiters; i++ {
		cr := mkResp(uint64(100+i), nil)
		first = append(first, cr)
		require.ErrorIs(t, f.verifyDeferred(&cr.UC, cr), ErrShardConfPending)
	}
	// the same certificate delivered again (another root) replaces its own entry: it supplies the same work
	again := mkResp(100, nil)
	require.ErrorIs(t, f.verifyDeferred(&again.UC, again), ErrShardConfPending)
	// a distinct one beyond the bound is refused, and nothing registered is dropped
	extra := mkResp(190, nil)
	err := f.verifyDeferred(&extra.UC, extra)
	require.ErrorIs(t, err, ErrShardConfBusy, "a refused response is reported as such, not as pending")
	require.NotErrorIs(t, err, ErrShardConfPending)
	f.c.reinject = make(chan any, 64)
	f.resolve()
	got := map[any]bool{}
	for len(f.c.reinject) > 0 {
		got[<-f.c.reinject] = true
	}
	require.Len(t, got, maxConfWaiters, "every registered response comes back, the refused one does not")
	require.True(t, got[again])
	require.False(t, got[first[0]], "replaced by its own duplicate")
	for _, cr := range first[1:] {
		require.True(t, got[cr])
	}
	require.False(t, got[extra])
}

func TestAnOlderCheckpointRetryNeverOverwritesANewerSave(t *testing.T) {
	f := newFollowFixture(t)
	first := f.cert(t, f.h1)
	require.ErrorIs(t, f.verify(first, 1), ErrShardConfPending)
	f.resolve()
	second := f.cert(t, f.h2)
	require.ErrorIs(t, f.verify(second, 2), ErrShardConfPending)
	f.resolve()
	f.c.publishConf(first)
	f.c.publishConf(second)
	// an older job that was copied before the newer save committed
	require.NoError(t, f.c.follow.writeCheckpoint(&checkpointJob{pdr: f.pdr1, uc: first}))
	pdr, _, err := loadConfCheckpoint(f.checkpoint)
	require.NoError(t, err)
	require.EqualValues(t, 2, pdr.Epoch, "the newer epoch stays on disk")
}

func TestTheLocalShardIsServedFirst(t *testing.T) {
	f := newFollowFixture(t)
	left, _ := types.ShardID{}.Split()
	f.srv.byEpoch[left.Key()] = map[uint64]*types.PartitionDescriptionRecord{}
	f.c.follow.request(left, []byte("older sibling"), []uint64{1}, nil)
	require.ErrorIs(t, f.verify(f.cert(t, f.h1)), ErrShardConfPending)
	f.resolve()
	require.Equal(t, types.ShardID{}.Key()+"@1", f.srv.calls[0], "the local shard's lookup first, whatever the age of the siblings'")
}

func TestTheBacklogCountsRegisteredAndResolvedResponsesTogether(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	left, _ := types.ShardID{}.Split()
	n := 0
	for lookup := 0; n < maxConfBacklog; lookup++ {
		for w := 0; w < maxConfWaiters && n < maxConfBacklog; w++ {
			require.Equal(t, confQueued, fl.request(left, []byte{byte(lookup), 7}, nil, new(int)))
			n++
		}
	}
	require.Equal(t, confRefused, fl.request(left, []byte("another lookup"), nil, new(int)), "the backlog is full")
	// resolving releases the pending slots but the responses are still held until handed back: the bound still holds
	fl.mu.Lock()
	for k, p := range fl.pending {
		fl.ready = append(fl.ready, p.waiters...)
		delete(fl.pending, k)
	}
	fl.mu.Unlock()
	require.Equal(t, confRefused, fl.request(left, []byte("yet another"), nil, new(int)), "undelivered resolved responses count against the backlog")
}

func TestAResponseWithADifferentSidecarIsDifferentWork(t *testing.T) {
	f := newFollowFixture(t)
	uc := f.cert(t, f.h1)
	a := &certification.CertificationResponse{Partition: utbtest.Partition, UC: *uc, PartitionView: []byte{1, 2, 3}}
	b := &certification.CertificationResponse{Partition: utbtest.Partition, UC: *uc, PartitionView: []byte{1, 2, 4}}
	require.NotEqual(t, waiterKey(a), waiterKey(b), "equal length, different bytes")
	require.Equal(t, waiterKey(a), waiterKey(&certification.CertificationResponse{Partition: utbtest.Partition, UC: *uc, PartitionView: []byte{1, 2, 3}}))
	// an invalid optional sidecar is validated before registering and left out of the replay
	op := f.c.authn.beginIntake(context.Background())
	op.deferred = a
	got := op.deferredResponse().(*certification.CertificationResponse)
	require.Nil(t, got.PartitionView, "a sidecar that does not validate is not registered")
	require.Equal(t, []byte{1, 2, 3}, a.PartitionView, "the original is not modified")
}

// Retention by need: the persisted set is the published configuration and the configurations the LATEST staged view needed, replaced as
// views advance; history never accumulates and never crowds out what the current view needs.
func TestThePersistedConfigurationsAreExactlyWhatTheLatestViewNeeds(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	fl.checkpoint = filepath.Join(t.TempDir(), "checkpoint.json")
	left, right := types.ShardID{}.Split()
	mk := func(shard types.ShardID, epoch uint64) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: utbtest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
			ShardID: shard, T2Timeout: time.Second, Epoch: epoch, EpochStart: epoch + 1}
	}
	slow := mk(right, 3) // a slow sibling, still what the current view needs
	slowHash := confHashOf(t, slow)
	fl.mu.Lock()
	fl.add(right, slowHash, slow)
	hashes := map[uint64][]byte{}
	for e := uint64(1); e <= 1500; e++ { // a long history of the other shard, each once needed by an earlier view
		p := mk(left, e)
		hashes[e] = confHashOf(t, p)
		fl.add(left, hashes[e], p)
	}
	fl.mu.Unlock()
	round := uint64(1)
	for e := uint64(1); e <= 1500; e += 100 {
		fl.setNeeded(map[string][]byte{left.Key(): hashes[e], right.Key(): slowHash}, round)
		round++
	}
	fl.setNeeded(map[string][]byte{left.Key(): hashes[1500], right.Key(): slowHash}, round)
	raw, err := os.ReadFile(fl.checkpoint + ".known")
	require.NoError(t, err)
	var saved []*types.PartitionDescriptionRecord
	require.NoError(t, json.Unmarshal(raw, &saved))
	require.Len(t, saved, 3, "the published configuration and the latest view's two: no history")
	epochs := map[string]uint64{}
	for _, p := range saved {
		epochs[p.ShardID.Key()] = p.Epoch
	}
	require.EqualValues(t, 1500, epochs[left.Key()])
	require.EqualValues(t, 3, epochs[right.Key()], "the slow sibling the current view needs is kept")
	first := raw
	fl.saveNeeded()
	again, _ := os.ReadFile(fl.checkpoint + ".known")
	require.Equal(t, first, again, "deterministic")
}

func TestAFailedKnownFileSaveIsRetried(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	fl.checkpoint = filepath.Join(blocker, "sub", "checkpoint.json")
	now := time.Unix(1000, 0)
	fl.now = func() time.Time { return now }
	fl.saveNeeded()
	require.True(t, fl.knownDirty)
	require.NoError(t, os.Remove(blocker))
	now = now.Add(checkpointRetry + time.Second)
	fl.retrySave()
	require.False(t, fl.knownDirty)
	_, err := os.Stat(fl.checkpoint + ".known")
	require.NoError(t, err)
}

// The budget is charged until a response is actually handed to the loop: a handback that fails leaves it queued in place and charged, so new
// admissions are refused rather than finding free slots, and order is kept.
func TestAResponseStaysChargedUntilItIsHandedBack(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	left, _ := types.ShardID{}.Split()
	var queued []*int
	for lookup := 0; len(queued) < maxConfBacklog; lookup++ {
		for w := 0; w < maxConfWaiters && len(queued) < maxConfBacklog; w++ {
			x := new(int)
			*x = len(queued)
			queued = append(queued, x)
			require.Equal(t, confQueued, fl.request(left, []byte{byte(lookup), 9}, nil, x))
		}
	}
	// every lookup resolves; the loop takes nothing
	var delivered []any
	taking := false
	fl.deliver = func(m any) bool {
		if taking {
			delivered = append(delivered, m)
		}
		return taking
	}
	fl.mu.Lock()
	for _, l := range fl.pending {
		l.next = time.Time{}
	}
	fl.mu.Unlock()
	for lookup := 0; lookup < maxConfBacklog/maxConfWaiters; lookup++ {
		fl.complete(&lookup2{shard: left, sealed: []byte{byte(lookup), 9}}, []byte{byte(lookup), 9}, &types.PartitionDescriptionRecord{})
	}
	require.Len(t, fl.ready, maxConfBacklog, "all queued, none handed back")
	require.Equal(t, confRefused, fl.request(left, []byte("new lookup"), nil, new(int)), "the detached slots do not look free")
	// the loop takes them again: in order, each removed only when taken
	taking = true
	fl.flush()
	require.Empty(t, fl.ready)
	require.Len(t, delivered, maxConfBacklog)
	for i, m := range delivered {
		require.Same(t, queued[i], m, "order is kept")
	}
	require.Equal(t, confQueued, fl.request(left, []byte("new lookup"), nil, new(int)), "charged slots are released on delivery")
}

type lookup2 = lookup

// An expired lookup and the fresh lookup registered under its key afterwards are separate: the old fetch completing hands back the
// registered one's responses exactly once, and the expired one's were handed back when it expired.
func TestExpiryAndAReplacementLookupDoNotLoseWaiters(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	now := time.Unix(1000, 0)
	fl.now = func() time.Time { return now }
	left, _ := types.ShardID{}.Split()
	sealed := []byte("sealed")
	w1, w2 := new(int), new(int)
	require.Equal(t, confQueued, fl.request(left, sealed, []uint64{1}, w1))
	key := left.Key() + "/" + string(sealed)
	old := fl.pending[key]
	var got []any
	fl.deliver = func(m any) bool { got = append(got, m); return true }
	// the old lookup is in flight (a fetch holds it) when it expires and intake registers a fresh one under the same key
	now = now.Add(confPendingTTL + time.Second)
	require.Equal(t, confQueued, fl.request(left, sealed, []uint64{1}, w2))
	require.NotSame(t, old, fl.pending[key], "a fresh lookup")
	require.Equal(t, []any{w1}, fl.ready, "the expired lookup's response was handed back by expiry, once")
	// the old fetch now succeeds
	fl.complete(old, sealed, &types.PartitionDescriptionRecord{})
	require.Equal(t, []any{w1, w2}, got, "each response exactly once, the replacement's included")
	require.Empty(t, fl.pending)
	require.Empty(t, fl.ready)
}

// Each file has its own retry schedule: a cache file that keeps failing never delays the live checkpoint.
func TestAFailingKnownFileDoesNotDelayTheCheckpointRetry(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	dir := t.TempDir()
	fl.checkpoint = filepath.Join(dir, "checkpoint.json")
	require.NoError(t, os.Mkdir(fl.checkpoint+".known", 0o700)) // the cache file cannot be replaced: every save of it fails
	now := time.Unix(1000, 0)
	fl.now = func() time.Time { return now }
	fl.saveNeeded()
	require.True(t, fl.knownDirty)
	// a checkpoint whose first save failed is due again
	second := f.cert(t, f.h2)
	require.ErrorIs(t, f.verify(second, 2), ErrShardConfPending)
	f.resolve()
	fl.mu.Lock()
	fl.latest = f.pdr2
	fl.unsaved = &checkpointJob{pdr: f.pdr2, uc: second}
	fl.nextSave = now.Add(checkpointRetry)
	fl.mu.Unlock()
	for i := 0; i < 3; i++ { // the cache keeps failing and pushing its own deadline
		now = now.Add(checkpointRetry + time.Second)
		fl.retrySave()
		if i == 0 {
			_, err := os.Stat(fl.checkpoint)
			require.NoError(t, err, "the checkpoint is written on its first due retry, whatever the cache does")
		}
	}
	require.Nil(t, fl.unsaved)
	require.True(t, fl.knownDirty)
}

// The need relation survives restarts: the persisted entries are what the latest view needed, and a restart recomputes the relation from
// them, so a later resolution never evicts a sibling the same view still needs.
func TestTheNeedRelationSurvivesRepeatedRestarts(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	fl.checkpoint = filepath.Join(t.TempDir(), "checkpoint.json")
	left, right := types.ShardID{}.Split()
	mk := func(shard types.ShardID, epoch uint64) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: utbtest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
			ShardID: shard, T2Timeout: time.Second, Epoch: epoch, EpochStart: epoch + 1}
	}
	sib := mk(right, 4)
	sibHash := confHashOf(t, sib)
	fl.mu.Lock()
	fl.add(right, sibHash, sib)
	fl.mu.Unlock()
	fl.setNeeded(map[string][]byte{right.Key(): sibHash}, 1)
	for restart := 0; restart < 3; restart++ {
		next := newShardConfFollower(f.srv, f.pdr0, f.h0)
		next.checkpoint = fl.checkpoint
		next.restoreKnown(fl.checkpoint)
		require.True(t, next.isKnown(right, sibHash), "restart %d keeps the sibling the view needs", restart)
		// something else is resolved after the restart, and saved: the sibling is still needed by the same view
		extra := mk(left, uint64(10+restart))
		next.mu.Lock()
		next.add(left, confHashOf(t, extra), extra)
		next.mu.Unlock()
		next.saveNeeded()
		fl = next
	}
	last := newShardConfFollower(f.srv, f.pdr0, f.h0)
	last.restoreKnown(fl.checkpoint)
	require.True(t, last.isKnown(right, sibHash), "still there after several restarts")
}

// A delayed replay of an older response never replaces the dependencies of a newer accepted view, and an unchanged set costs no disk write.
func TestADelayedReplayNeverReplacesTheNewerViewsDependencies(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	fl.checkpoint = filepath.Join(t.TempDir(), "checkpoint.json")
	left, right := types.ShardID{}.Split()
	mk := func(shard types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, []byte) {
		p := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: utbtest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
			ShardID: shard, T2Timeout: time.Second, Epoch: epoch, EpochStart: epoch + 1}
		return p, confHashOf(t, p)
	}
	oldSib, oldHash := mk(right, 1)
	newSib, newHash := mk(right, 2)
	fl.mu.Lock()
	fl.add(right, oldHash, oldSib)
	fl.add(right, newHash, newSib)
	fl.mu.Unlock()
	fl.setNeeded(map[string][]byte{right.Key(): newHash}, 200) // the newer accepted view
	_ = left
	fl.setNeeded(map[string][]byte{right.Key(): oldHash}, 150) // an older authentic response resolving late: its certificate is stale
	read := func() []*types.PartitionDescriptionRecord {
		raw, err := os.ReadFile(fl.checkpoint + ".known")
		require.NoError(t, err)
		var saved []*types.PartitionDescriptionRecord
		require.NoError(t, json.Unmarshal(raw, &saved))
		return saved
	}
	require.EqualValues(t, 2, read()[len(read())-1].Epoch, "the newer view's dependency stays")
	// a restart still has what the finalized view needs
	next := newShardConfFollower(f.srv, f.pdr0, f.h0)
	next.restoreKnown(fl.checkpoint)
	require.True(t, next.isKnown(right, newHash))

	// the same set again costs no write
	info, err := os.Stat(fl.checkpoint + ".known")
	require.NoError(t, err)
	before := info.ModTime()
	require.NoError(t, os.Chtimes(fl.checkpoint+".known", before.Add(-time.Hour), before.Add(-time.Hour)))
	fl.setNeeded(map[string][]byte{right.Key(): newHash}, 300)
	fl.saveNeeded()
	info, err = os.Stat(fl.checkpoint + ".known")
	require.NoError(t, err)
	require.True(t, info.ModTime().Before(before), "an unchanged dependency set is not rewritten")
}

// Taking a response and releasing its charge are one step: the loop re-registering an expired response the moment it receives it finds its own
// slot released, never a full budget.
func TestAnExpiredResponseIsNotRefusedAgainstItsOwnSlot(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	left, _ := types.ShardID{}.Split()
	// the budget is full: 255 responses registered with lookups, one more resolved and queued for handback
	for lookup := 0; len(fl.pending)*maxConfWaiters < maxConfBacklog-maxConfWaiters; lookup++ {
		for w := 0; w < maxConfWaiters; w++ {
			require.Equal(t, confQueued, fl.request(left, []byte{byte(lookup), 3}, nil, new(int)))
		}
	}
	last := new(int)
	fl.mu.Lock()
	for fl.backlogLocked() < maxConfBacklog-1 {
		fl.ready = append(fl.ready, new(int))
	}
	fl.ready = append(fl.ready, last)
	fl.mu.Unlock()
	require.Equal(t, maxConfBacklog, fl.backlogLocked())
	// the loop takes each response and re-registers it at once, from another goroutine, as the message loop does
	var wg sync.WaitGroup
	results := make(chan confResult, 1)
	fl.deliver = func(m any) bool {
		if m == any(last) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- fl.request(left, []byte("the expired lookup, again"), nil, m)
			}()
		}
		return true
	}
	fl.flush()
	wg.Wait()
	require.Equal(t, confQueued, <-results, "its own slot was released with the delivery")
}

// A restart: the durable finalized block and its UC are the source of truth. Whatever the cache file holds (nothing, or the dependencies of a
// different, newer view because a round was started without finalizing, or a block was finalized and the next round failed to start), the
// publisher resolves the configurations the block's sidecar needs through the seal-verified worker and attaches the sidecar when they resolve.
func TestARestartResolvesTheFinalizedBlocksConfigurationsFromTheBlockItself(t *testing.T) {
	for name, cache := range map[string]string{"no cache": "", "cache of a newer view": "newer", "cache of an older view": "older"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			backend := smtbackend.NewMemoryBackend(smt.NewThreadSafeSMT(smt.NewSparseMerkleTree(api.SHA256, api.StateTreeKeyLengthBits)))
			snap, err := backend.CreateSnapshot(ctx)
			require.NoError(t, err)
			key := make([]byte, api.StateTreeKeyLengthBytes)
			key[0] = 7
			res, err := snap.AddLeavesClassified(ctx, []smtbackend.LeafInput{{Key: key, Value: make([]byte, 32)}})
			require.NoError(t, err)
			require.NoError(t, snap.Commit(ctx, smtbackend.CommitMetadata{BlockNumber: api.NewBigIntFromUint64(5), RootHash: res.CandidateRoot}))
			root := res.CandidateRoot

			before := prooftest.New(t, 2, 7, root, 80)
			order, err := types.CanonicalShardOrder(before.Topo.Scheme)
			require.NoError(t, err)
			ours, sibling := order[0], order[1]
			node := func(id string) *types.NodeInfo {
				return &types.NodeInfo{NodeID: id, SigKey: []byte{2, byte(len(id))}, Stake: 1}
			}
			mk := func(shard types.ShardID, epoch uint64, ids ...string) *types.PartitionDescriptionRecord {
				p := &types.PartitionDescriptionRecord{Version: 1, NetworkID: prooftest.NetworkID, PartitionID: prooftest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
					ShardID: shard, T2Timeout: time.Second, Epoch: epoch, EpochStart: 1 + epoch*100}
				for _, id := range ids {
					p.Validators = append(p.Validators, node(id))
				}
				return p
			}
			ours0, ours1, sib1 := mk(ours, 0, "o1"), mk(ours, 1, "o1", "o2"), mk(sibling, 1, "s1", "s2")
			after := prooftest.NewWithConfs(t, prooftest.Partition, 2, 8, root, 90, map[string][]byte{ours.Key(): confHashOf(t, ours1), sibling.Key(): confHashOf(t, sib1)})
			ucBytes, err := types.Cbor.Marshal(after.UC)
			require.NoError(t, err)
			block := models.NewBlock(api.NewBigIntFromUint64(5), "unicity", 0, "1.0", "mainnet", api.NewHexBytes(root), api.NewHexBytes(prooftest.Hash("prev")), api.NewHexBytes(ucBytes), 1)
			block.Finalized = true
			block.PartitionView = api.NewHexBytes(after.Raw)

			// the cache file of the previous process: whatever it holds, the block does not depend on it
			cp := filepath.Join(t.TempDir(), "checkpoint.json")
			if cache != "" {
				other := mk(sibling, 9, "x")
				raw, err := json.Marshal([]*types.PartitionDescriptionRecord{other})
				require.NoError(t, err)
				if cache == "older" {
					raw, err = json.Marshal([]*types.PartitionDescriptionRecord{mk(sibling, 0, "s0")})
					require.NoError(t, err)
				}
				require.NoError(t, os.WriteFile(cp+".known", raw, 0o600))
			}

			c, _ := newProofClient(t, &stubRoundManager{}, before)
			c.shardID = ours
			topo := c.proofTopology.(*proofmaterial.StaticTopology)
			topo.SetFollowing(map[string]bool{ours.Key(): true, sibling.Key(): true})
			src := &confServer{byEpoch: map[string]map[uint64]*types.PartitionDescriptionRecord{ours.Key(): {1: ours1}, sibling.Key(): {1: sib1}}}
			fl := newShardConfFollower(src, ours0, before.Topo.ShardConfHashes[ours.Key()])
			fl.checkpoint = cp
			fl.restoreKnown(cp)
			fl.deliver = c.redeliver
			c.follow = fl
			c.reinject = make(chan any, 4)
			c.authn.withShardConfFollower(fl, before.Topo.ShardConfHashes[ours.Key()])
			c.followTopology()

			log, err := logger.New("error", "json", "", false)
			require.NoError(t, err)
			cat, err := proofview.NewCatalog(proofview.DefaultLimits())
			require.NoError(t, err)
			t.Cleanup(func() { _ = cat.Close() })
			pub := proofpub.New(cat, backend, c.proofTopology, log)
			require.NotNil(t, pub)
			pub.SetSealVerifier(before.Verifier())
			pub.SetViewConfigs(c)

			pub.EnsurePublishedAtStartup(ctx, block)
			lease, err := cat.AcquireLatest(ctx)
			require.NoError(t, err)
			require.Nil(t, lease.PartitionView(), "published without the sidecar until its configurations resolve")
			lease.Release()

			require.Eventually(t, func() bool {
				fl.process(ctx) // the existing worker, the seal-verified path (the publisher queues the lookups just after publishing the block)
				l, err := cat.AcquireLatest(ctx)
				if err != nil {
					return false
				}
				defer l.Release()
				return bytes.Equal(l.PartitionView(), after.Raw)
			}, 5*time.Second, 10*time.Millisecond, "the sidecar is attached once the configurations resolve")
		})
	}
}

// The worker runs by itself on the first lookup, for the life of the process: a passive HA replica needs no activation.
func TestTheWorkerStartsOnTheFirstLookupWithoutActivation(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	fl.autostart = true
	fl.source = &instantSource{pdr: f.pdr1}
	done := make(chan struct{})
	require.Equal(t, confQueued, fl.request(types.ShardID{}, f.h1, []uint64{1}, &confCallback{fn: func() { close(done) }}))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the callback of a lookup was never run: no worker")
	}
}

// Expiry is not resolution: a lookup a durable view's callback waits for outlives the TTL, is retried with its backoff, and runs the callback
// only when its configuration is actually known.
func TestExpiryIsNotResolutionForADurableViewsCallback(t *testing.T) {
	f := newFollowFixture(t)
	fl := f.c.follow
	now := time.Unix(1000, 0)
	fl.now = func() time.Time { return now }
	f.srv.fail = errors.New("source down")
	var ran atomic.Int32
	require.Equal(t, confQueued, fl.request(types.ShardID{}, f.h1, []uint64{1}, &confCallback{fn: func() { ran.Add(1) }}))
	replay := &certification.CertificationResponse{Partition: utbtest.Partition}
	require.Equal(t, confQueued, fl.request(types.ShardID{}, f.h1, []uint64{1}, replay))
	fl.process(context.Background())
	// a ten minute outage
	now = now.Add(confPendingTTL + time.Second)
	fl.process(context.Background())
	require.Zero(t, ran.Load(), "expiry did not run the callback")
	require.Len(t, fl.pending, 1, "the lookup the durable view waits for is retained")
	select {
	case got := <-f.c.reinject:
		require.Same(t, replay, got, "while a response to replay is handed back")
	default:
		t.Fatal("the response to replay was not handed back")
	}
	// the source recovers: the retry (after its backoff) resolves it and only then does the callback run
	f.srv.fail = nil
	now = now.Add(confBackoffMax + time.Second)
	fl.process(context.Background())
	require.Eventually(t, func() bool { return ran.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	require.Empty(t, fl.pending)
}

// With two needed configurations, the first can resolve before the second is found to be known already: the registration that completes
// the set must run the callback (it used to report "nothing pending" and the view was dropped although every configuration was known).
func TestAViewWithTwoNeedsAlwaysCompletesItsCallback(t *testing.T) {
	root := prooftest.Hash("root-1")
	before := prooftest.New(t, 2, 7, root, 80)
	order, err := types.CanonicalShardOrder(before.Topo.Scheme)
	require.NoError(t, err)
	ours, sibling := order[0], order[1]
	mk := func(shard types.ShardID, epoch uint64) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{Version: 1, NetworkID: prooftest.NetworkID, PartitionID: prooftest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
			ShardID: shard, T2Timeout: time.Second, Epoch: epoch, EpochStart: 1 + epoch*100,
			Validators: []*types.NodeInfo{{NodeID: "n", SigKey: []byte{2, 1}, Stake: 1}}}
	}
	ours0, ours1, sib1 := mk(ours, 0), mk(ours, 1), mk(sibling, 1)
	after := prooftest.NewWithConfs(t, prooftest.Partition, 2, 8, root, 90, map[string][]byte{ours.Key(): confHashOf(t, ours1), sibling.Key(): confHashOf(t, sib1)})
	for i := 0; i < 200; i++ {
		c, _ := newProofClient(t, &stubRoundManager{}, before)
		c.shardID = ours
		topo := c.proofTopology.(*proofmaterial.StaticTopology)
		topo.SetFollowing(map[string]bool{ours.Key(): true, sibling.Key(): true})
		src := &confServer{byEpoch: map[string]map[uint64]*types.PartitionDescriptionRecord{ours.Key(): {1: ours1}, sibling.Key(): {1: sib1}}}
		fl := newShardConfFollower(src, ours0, before.Topo.ShardConfHashes[ours.Key()])
		fl.autostart = true
		fl.deliver = c.redeliver
		c.follow = fl
		c.authn.withShardConfFollower(fl, before.Topo.ShardConfHashes[ours.Key()])
		c.followTopology()
		var ran atomic.Int32
		pending := c.PendingViewConfigs(after.Raw, after.UC, before.Verifier()(context.Background()), func() { ran.Add(1) })
		require.True(t, pending, "round %d: both configurations are unknown at first", i)
		require.Eventually(t, func() bool { return ran.Load() >= 1 }, 5*time.Second, time.Millisecond, "round %d: the callback never ran", i)
		time.Sleep(time.Millisecond)
		require.EqualValues(t, 1, ran.Load(), "round %d: exactly once", i)
	}
}

// A source installed through the public setter starts the worker on its first lookup, like the constructor's.
func TestASourceInstalledThroughTheSetterStartsTheWorker(t *testing.T) {
	c, _, _, _, _, _ := threeEpochs(t, utbtest.Partition)
	node := &types.NodeInfo{NodeID: "a1", SigKey: []byte{2, 1}, Stake: 1}
	pdr0 := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: utbtest.Partition, PartitionTypeID: 7, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: time.Second, Epoch: 0, EpochStart: 1, Validators: []*types.NodeInfo{node}}
	pdr1 := *pdr0
	pdr1.Epoch, pdr1.EpochStart = 1, 100
	c.conf.ShardConf = pdr0
	c.authn.withShardConfHash(confHashOf(t, pdr0))
	c.SetShardConfSource(&instantSource{pdr: &pdr1}) // the public setter
	require.True(t, c.follow.autostart)
	done := make(chan struct{})
	require.Equal(t, confQueued, c.follow.request(types.ShardID{}, confHashOf(t, &pdr1), []uint64{1}, &confCallback{fn: func() { close(done) }}))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no worker ran for a source installed through the setter")
	}
}
