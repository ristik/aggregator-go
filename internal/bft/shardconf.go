package bft

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Following the shard's configuration across a live change (validator-registry kinds 6 ReplaceAggregatorValidators and 8 UpdatePartition).
//
// A change replaces the shard's PartitionDescriptionRecord at an activation round: the root certifies the successor's hash in every
// certificate of the new shard epoch, so a client that pins the hash of the configuration it started with would refuse them all.
//
// Authority. The shard configuration hash is part of what the root seal signs. A certificate (or partition view leaf) that authenticates
// and commits to a hash the client does not hold is the root quorum's statement of a configuration of that shard. The client resolves the
// hash to a configuration through a ShardConfSource (a root's public GET /api/v1/shardConf), requires the answer to hash to exactly the
// sealed value and to be a configuration of the same network, partition and shard at the epoch asked for, and only then adds it to the
// configurations it knows. Nothing a root serves is trusted without that hash.
//
// Availability. Resolution never runs on the message loop. An authentic certificate with an unknown hash is dropped with
// ErrShardConfPending and the hash is queued (coalesced by shard and hash); one worker fetches it with a total time budget, directly at
// the epoch the authenticated certificate names (the technical record's epoch, the input record's epoch and its successor: no search
// across epochs), backs off exponentially after a failure, and on success hands the dropped certificate back to the message loop.
//
// Publication. Knowing a configuration only lets certificates that commit to it verify, so historical certificates keep verifying against
// the configuration they were certified under and a certificate that is then discarded as stale changes nothing. The configuration of
// the newest certificate the sequence checks accepted is published (publish), and only that is persisted in the checkpoint a restart
// resumes from.

// ShardConfSource serves the configuration of one epoch of a shard (a root's GET /api/v1/shardConf). Its answer is untrusted: the client
// checks it against the sealed hash.
type ShardConfSource interface {
	ShardConfig(ctx context.Context, partition types.PartitionID, shard types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error)
}

// ErrShardConfPending reports an authentic certificate whose configuration is being resolved: it is dropped and handed back on success.
var ErrShardConfPending = errors.New("shard configuration is being resolved")

const (
	confFetchBudget  = 15 * time.Second // the total time one resolution may take, all attempts included
	confBackoffFirst = time.Second
	confBackoffMax   = time.Minute
	maxPendingConfs  = 64
	maxConfHints     = 4
)

type pendingConf struct {
	shard  types.ShardID
	sealed []byte
	hints  []uint64
	fails  int
	next   time.Time
}

// shardConfFollower resolves and holds the configurations of the shard (and, for the consolidation topology, of its siblings).
type shardConfFollower struct {
	source    ShardConfSource
	network   types.NetworkID
	partition types.PartitionID
	ours      types.ShardID
	now       func() time.Time

	mu      sync.Mutex
	known   map[string]map[string]*types.PartitionDescriptionRecord // shard key -> sealed hash -> configuration
	pending map[string]*pendingConf
	latest  *types.PartitionDescriptionRecord // the published configuration of our shard
	wake    chan struct{}
	// resolved is called (outside the lock) after a resolution succeeded: the dropped certificate is re-admitted
	resolved func()
	// checkpoint is the file the published configuration is persisted in ("" none)
	checkpoint string
}

func newShardConfFollower(source ShardConfSource, start *types.PartitionDescriptionRecord, startHash []byte) *shardConfFollower {
	f := &shardConfFollower{source: source, network: start.NetworkID, partition: start.PartitionID, ours: start.ShardID, now: time.Now,
		known: map[string]map[string]*types.PartitionDescriptionRecord{}, pending: map[string]*pendingConf{}, wake: make(chan struct{}, 1), latest: start}
	f.add(start.ShardID, startHash, start)
	return f
}

func (f *shardConfFollower) add(shard types.ShardID, hash []byte, pdr *types.PartitionDescriptionRecord) {
	k := shard.Key()
	if f.known[k] == nil {
		f.known[k] = map[string]*types.PartitionDescriptionRecord{}
	}
	f.known[k][string(hash)] = pdr
}

// isKnown reports whether hash is a verified configuration of the shard.
func (f *shardConfFollower) isKnown(shard types.ShardID, hash []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.known[shard.Key()][string(hash)]
	return ok
}

// request queues the resolution of the sealed hash of a shard's configuration. hints are the shard epochs it can be (from authenticated
// records); a request already queued is coalesced and only gains hints.
func (f *shardConfFollower) request(shard types.ShardID, sealed []byte, hints []uint64) {
	f.mu.Lock()
	key := shard.Key() + "/" + string(sealed)
	if _, ok := f.known[shard.Key()][string(sealed)]; ok {
		f.mu.Unlock()
		return
	}
	p := f.pending[key]
	if p == nil {
		if len(f.pending) >= maxPendingConfs {
			f.mu.Unlock()
			return
		}
		p = &pendingConf{shard: shard, sealed: bytes.Clone(sealed), next: f.now()}
		f.pending[key] = p
	}
	for _, h := range hints {
		if len(p.hints) < maxConfHints && !containsEpoch(p.hints, h) {
			p.hints = append(p.hints, h)
		}
	}
	due := !p.next.After(f.now())
	f.mu.Unlock()
	if due {
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
}

func containsEpoch(s []uint64, v uint64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// run is the worker: one goroutine, one resolution at a time.
func (f *shardConfFollower) run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.wake:
		case <-tick.C:
		}
		f.process(ctx)
	}
}

// process resolves every queued request that is due.
func (f *shardConfFollower) process(ctx context.Context) {
	f.mu.Lock()
	var due []*pendingConf
	for _, p := range f.pending {
		if !p.next.After(f.now()) {
			due = append(due, p)
		}
	}
	f.mu.Unlock()
	for _, p := range due {
		if ctx.Err() != nil {
			return
		}
		f.resolve(ctx, p)
	}
}

func (f *shardConfFollower) resolve(ctx context.Context, p *pendingConf) {
	ctx, cancel := context.WithTimeout(ctx, confFetchBudget)
	defer cancel()
	f.mu.Lock()
	hints := append([]uint64(nil), p.hints...)
	f.mu.Unlock()
	var last error = errors.New("no epoch to try")
	for _, epoch := range hints {
		pdr, err := f.source.ShardConfig(ctx, f.partition, p.shard, epoch)
		if err != nil {
			last = err
			break // the source is failing: back off rather than spend the budget on the other hints
		}
		if pdr == nil {
			last = fmt.Errorf("no epoch %d is served", epoch)
			continue
		}
		h, err := pdr.Hash(crypto.SHA256)
		if err != nil || pdr.Epoch != epoch || pdr.NetworkID != f.network || pdr.PartitionID != f.partition || !pdr.ShardID.Equal(p.shard) {
			last = fmt.Errorf("the configuration served for epoch %d is not a configuration of this shard", epoch)
			continue
		}
		if !bytes.Equal(h, p.sealed) {
			last = fmt.Errorf("the configuration served for epoch %d does not hash to the sealed value", epoch)
			continue
		}
		f.mu.Lock()
		f.add(p.shard, h, pdr)
		delete(f.pending, p.shard.Key()+"/"+string(p.sealed))
		cb := f.resolved
		f.mu.Unlock()
		if cb != nil {
			cb()
		}
		return
	}
	f.mu.Lock()
	p.fails++
	back := confBackoffFirst << min(p.fails-1, 6)
	if back > confBackoffMax {
		back = confBackoffMax
	}
	p.next = f.now().Add(back)
	f.mu.Unlock()
	_ = last
}

// publish makes the configuration an accepted certificate commits to the live configuration of our shard, when it is a later epoch than the
// one published, and persists it with the certificate that authenticates it. It returns the published configuration.
func (f *shardConfFollower) publish(uc *types.UnicityCertificate) (*types.PartitionDescriptionRecord, bool, error) {
	f.mu.Lock()
	pdr := f.known[f.ours.Key()][string(uc.ShardConfHash)]
	if pdr == nil || pdr.Epoch <= f.latest.Epoch {
		f.mu.Unlock()
		return nil, false, nil
	}
	f.latest = pdr
	path := f.checkpoint
	f.mu.Unlock()
	var err error
	if path != "" {
		err = saveConfCheckpoint(path, pdr, uc) // best effort: without it a restart resolves again from the file configuration
	}
	return pdr, true, err
}

// confCheckpoint is the authenticated record a restart resumes from: the published configuration and the certificate whose seal committed to
// its hash. A restart verifies both again before trusting either.
type confCheckpoint struct {
	PDR *types.PartitionDescriptionRecord `json:"pdr"`
	UC  []byte                            `json:"uc"`
}

func saveConfCheckpoint(path string, pdr *types.PartitionDescriptionRecord, uc *types.UnicityCertificate) error {
	raw, err := types.Cbor.Marshal(uc)
	if err != nil {
		return err
	}
	out, err := json.Marshal(confCheckpoint{PDR: pdr, UC: raw})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".shardconf-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func loadConfCheckpoint(path string) (*types.PartitionDescriptionRecord, *types.UnicityCertificate, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, nil, err
	}
	var cp confCheckpoint
	if err := json.Unmarshal(raw, &cp); err != nil || cp.PDR == nil {
		return nil, nil, fmt.Errorf("decoding the checkpoint: %v", err)
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(cp.UC, &uc); err != nil {
		return nil, nil, fmt.Errorf("decoding the checkpoint certificate: %w", err)
	}
	return cp.PDR, &uc, nil
}

// restore resumes from a checkpoint: it is accepted only when its certificate authenticates under the root seal (verify) and commits to
// exactly the hash of its configuration, which is a later epoch of this shard than the one the client started with.
func (f *shardConfFollower) restore(path string, verify func(uc *types.UnicityCertificate) error) error {
	pdr, uc, err := loadConfCheckpoint(path)
	if err != nil {
		return err
	}
	h, err := pdr.Hash(crypto.SHA256)
	if err != nil {
		return err
	}
	if !bytes.Equal(h, uc.ShardConfHash) || pdr.NetworkID != f.network || pdr.PartitionID != f.partition || !pdr.ShardID.Equal(f.ours) {
		return errors.New("the checkpoint configuration is not the one its certificate commits to, or is of another shard")
	}
	f.mu.Lock()
	later := pdr.Epoch > f.latest.Epoch
	f.mu.Unlock()
	if !later {
		return nil
	}
	if err := verify(uc); err != nil {
		return fmt.Errorf("the checkpoint certificate does not authenticate: %w", err)
	}
	f.mu.Lock()
	f.add(f.ours, h, pdr)
	f.latest = pdr
	f.mu.Unlock()
	return nil
}

// latestHash is the hash of the published configuration of our shard.
func (f *shardConfFollower) latestHash() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, err := f.latest.Hash(crypto.SHA256)
	if err != nil {
		return nil
	}
	return h
}
