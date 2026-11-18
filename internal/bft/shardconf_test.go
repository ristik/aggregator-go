package bft

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
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
	f.c.SetShardConfSource(f.srv)
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
	f.c.SetShardConfSource(f.srv)
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
	f.c.SetShardConfSource(f.srv)
	require.Equal(t, f.h0, f.c.authn.currentConfHash(), "a checkpoint that does not authenticate is ignored")
	// so is one whose certificate is not the quorum's
	bad := utbtest.CertificateWithConf(t, 5, 2, 999, f.signers[:1], make([]byte, 32), f.h2)
	require.NoError(t, saveConfCheckpoint(f.checkpoint, pdr, bad))
	f.c.follow, f.c.reinject = nil, nil
	f.c.authn.withShardConfHash(f.h0)
	f.c.SetShardConfSource(f.srv)
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
}
