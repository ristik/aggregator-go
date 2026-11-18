package bft

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/proofmaterial"
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
	maxConfWaiters   = 16               // distinct deferred responses kept per pending resolution; beyond it a new one is refused (backpressure), none is dropped
	maxConfBacklog   = 256              // deferred responses held at once, registered and resolved-but-not-yet-handed-back together
	maxKnownSaved    = 1024             // configurations persisted beside the checkpoint
	confPendingTTL   = 10 * time.Minute // a resolution unresolved for this long is obsolete (the shard moved on or the hash is not a configuration) and is reclaimed
	checkpointRetry  = 30 * time.Second // between attempts to persist a checkpoint that failed to save
)

type pendingConf struct {
	shard   types.ShardID
	sealed  []byte
	hints   []uint64
	fails   int
	next    time.Time
	born    time.Time
	local   bool  // the configuration of our own shard (current progress), which has priority over a sibling's
	waiters []any // the deferred responses that registered this lookup, handed back once it resolves
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
	// deliver hands a deferred response back to the message loop; it reports whether it was taken (the channel may be full)
	deliver func(any) bool
	ready   []any // resolved responses not yet taken, retried by the worker
	// checkpoint is the file the published configuration is persisted in ("" none); unsaved is the checkpoint whose save failed, retried
	checkpoint string
	unsaved    *checkpointJob
	nextSave   time.Time
	retained   map[string]bool // shard key/hash of the configurations staged views needed
	knownDirty bool            // the known-configuration file failed to save
	saveMu     sync.Mutex      // serializes the writers of the checkpoint and the known-configuration file
}

type checkpointJob struct {
	pdr *types.PartitionDescriptionRecord
	uc  *types.UnicityCertificate
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

// confResult is the outcome of queueing a lookup.
type confResult int

const (
	confQueued  confResult = iota // the lookup is queued and the response (if any) is registered with it
	confKnown                     // the configuration is known already: nothing to defer
	confRefused                   // no capacity (pending lookups, waiters of the lookup, or the backlog): nothing was registered
)

// ErrShardConfBusy reports an authentic certificate (or view) that could not be deferred for lack of capacity: it is refused, not pending,
// and is reported; the root sends the certificate again (the inactivity recovery asks for it).
var ErrShardConfBusy = errors.New("shard configuration lookups are at capacity")

// request queues the resolution of the sealed hash of a shard's configuration. hints are the shard epochs it can be (from authenticated
// records); a request already queued is coalesced and only gains hints. waiter, when not nil, is the deferred response that needs it: it is
// registered with the lookup before the worker is woken, kept until it is handed back, and delivered once the lookup resolves. It reports
// whether the configuration is known already (a resolution finished first): the caller then does not defer.
func (f *shardConfFollower) request(shard types.ShardID, sealed []byte, hints []uint64, waiter any) confResult {
	f.mu.Lock()
	if _, ok := f.known[shard.Key()][string(sealed)]; ok {
		f.mu.Unlock()
		return confKnown
	}
	key := shard.Key() + "/" + string(sealed)
	now := f.now()
	f.expireLocked(now) // an obsolete lookup of this hash is dropped first: a certificate that still needs it queues it afresh
	p := f.pending[key]
	if p == nil {
		local := shard.Equal(f.ours)
		if len(f.pending) >= maxPendingConfs && !f.reclaimLocked(now, local) {
			f.mu.Unlock()
			return confRefused
		}
		p = &pendingConf{shard: shard, sealed: bytes.Clone(sealed), next: now, born: now, local: local}
		f.pending[key] = p
	}
	for _, h := range hints {
		if len(p.hints) < maxConfHints && !containsEpoch(p.hints, h) {
			p.hints = append(p.hints, h)
		}
	}
	if waiter != nil {
		key := waiterKey(waiter)
		replaced := false
		for i, w := range p.waiters {
			if waiterKey(w) == key { // the same certificate delivered again (another root, a repeat): it satisfies the same work
				p.waiters[i], replaced = waiter, true
				break
			}
		}
		if !replaced {
			if len(p.waiters) >= maxConfWaiters || f.backlogLocked() >= maxConfBacklog {
				f.mu.Unlock()
				return confRefused // nothing already registered is dropped; this delivery is refused, and the caller reports it
			}
			p.waiters = append(p.waiters, waiter)
		}
	}
	due := !p.next.After(now)
	f.mu.Unlock()
	if due {
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
	return confQueued
}

// backlogLocked counts the deferred responses held: registered with a lookup and resolved but not yet handed back.
func (f *shardConfFollower) backlogLocked() int {
	n := len(f.ready)
	for _, p := range f.pending {
		n += len(p.waiters)
	}
	return n
}

// reclaimLocked makes room for a request: it drops the resolutions that are obsolete (older than confPendingTTL), and, for the local shard's
// current progress, the oldest resolution of a sibling. It reports whether there is room now.
func (f *shardConfFollower) reclaimLocked(now time.Time, local bool) bool {
	f.expireLocked(now)
	if len(f.pending) < maxPendingConfs {
		return true
	}
	if !local {
		return false
	}
	var oldest string
	var at time.Time
	for k, p := range f.pending {
		if !p.local && len(p.waiters) == 0 && (oldest == "" || p.born.Before(at)) { // a lookup that holds a response is never evicted
			oldest, at = k, p.born
		}
	}
	if oldest == "" {
		return false
	}
	delete(f.pending, oldest)
	return true
}

func (f *shardConfFollower) expireLocked(now time.Time) {
	for k, p := range f.pending {
		if now.Sub(p.born) > confPendingTTL {
			f.ready = append(f.ready, p.waiters...) // handed back: the message loop verifies it again and queues a fresh lookup if still needed
			delete(f.pending, k)
		}
	}
}

// waiterKey identifies the work a deferred response stands for: the whole response, certificate and sidecar bytes. Two responses with the same
// key supply the same certificate and the same view, so one replaces the other; anything that differs is separate work.
func waiterKey(w any) string {
	if cr, ok := w.(*certification.CertificationResponse); ok && cr != nil {
		if d, _, err := proofmaterial.DigestOfUC(&cr.UC); err == nil {
			h := sha256.New()
			h.Write(d[:])
			h.Write(cr.PartitionView)
			return fmt.Sprintf("%x", h.Sum(nil))
		}
	}
	return fmt.Sprintf("%p", w)
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
	f.flush()
	f.retrySave()
	f.mu.Lock()
	f.expireLocked(f.now())
	var due []*pendingConf
	for _, p := range f.pending {
		if !p.next.After(f.now()) {
			due = append(due, p)
		}
	}
	// the local shard's current progress is served first, then the oldest
	sort.Slice(due, func(i, j int) bool {
		if due[i].local != due[j].local {
			return due[i].local
		}
		return due[i].born.Before(due[j].born)
	})
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
		f.ready = append(f.ready, p.waiters...) // bounded by the registered waiters (maxPendingConfs x maxConfWaiters): never evicted
		p.waiters = nil
		f.mu.Unlock()
		f.saveKnown()
		f.flush()
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
		if err = f.writeCheckpoint(&checkpointJob{pdr: pdr, uc: uc}); err != nil {
			f.mu.Lock()
			f.unsaved, f.nextSave = &checkpointJob{pdr: pdr, uc: uc}, f.now().Add(checkpointRetry) // retried by the worker
			f.mu.Unlock()
		} else {
			f.mu.Lock()
			f.unsaved = nil
			f.mu.Unlock()
		}
	}
	return pdr, true, err
}

// flush hands resolved responses back to the message loop; those it does not take stay for the next pass.
func (f *shardConfFollower) flush() {
	f.mu.Lock()
	deliver := f.deliver
	ready := f.ready
	f.ready = nil
	f.mu.Unlock()
	if deliver == nil {
		return
	}
	var kept []any
	for _, m := range ready {
		if !deliver(m) {
			kept = append(kept, m)
		}
	}
	if len(kept) > 0 {
		f.mu.Lock()
		f.ready = append(kept, f.ready...)
		f.mu.Unlock()
	}
}

// writeCheckpoint persists a checkpoint. Writers are serialized and a checkpoint older than the published configuration is never written, so
// a retry of an older epoch cannot replace a newer save.
func (f *shardConfFollower) writeCheckpoint(job *checkpointJob) error {
	f.saveMu.Lock()
	defer f.saveMu.Unlock()
	f.mu.Lock()
	stale, path := job.pdr.Epoch < f.latest.Epoch, f.checkpoint
	f.mu.Unlock()
	if stale || path == "" {
		return nil
	}
	return saveConfCheckpoint(path, job.pdr, job.uc)
}

// retrySave persists a checkpoint whose save failed, as soon as the retry interval has passed.
func (f *shardConfFollower) retrySave() {
	f.mu.Lock()
	dirty, dueKnown := f.knownDirty, !f.now().Before(f.nextSave)
	f.mu.Unlock()
	if dirty && dueKnown {
		f.saveKnown()
	}
	f.mu.Lock()
	job, path, due := f.unsaved, f.checkpoint, !f.now().Before(f.nextSave)
	f.mu.Unlock()
	if job == nil || path == "" || !due {
		return
	}
	err := f.writeCheckpoint(job)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.nextSave = f.now().Add(checkpointRetry)
	} else if f.unsaved == job { // not replaced by a newer configuration meanwhile
		f.unsaved = nil
	}
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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

// The configurations this client resolved are persisted beside the checkpoint (<checkpoint>.known) so a restarted process, and the proof
// publisher that revalidates stored views with it, can validate a split view whose other shards changed. Each entry is checked against its own
// hash and the shard identity when read; an entry only widens which seal-authenticated leaf hashes a following pin accepts, and the leaf
// itself is authenticated by the seal.
func (f *shardConfFollower) saveKnown() {
	f.mu.Lock()
	path := f.checkpoint
	type entry struct {
		shard types.ShardID
		hash  string
		pdr   *types.PartitionDescriptionRecord
		rank  int // 0: retained by a staged view, 1: the newest of its shard, 2: the rest
	}
	var all []entry
	for k, byHash := range f.known {
		var newest uint64
		for _, pdr := range byHash {
			if pdr.Epoch > newest {
				newest = pdr.Epoch
			}
		}
		for h, pdr := range byHash {
			rank := 2
			if pdr.Epoch == newest {
				rank = 1
			}
			if f.retained[k+"/"+h] {
				rank = 0
			}
			all = append(all, entry{pdr.ShardID, h, pdr, rank})
		}
	}
	f.mu.Unlock()
	if path == "" {
		return
	}
	// deterministic: what the staged views and the current topology need first, then the newest epochs
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.pdr.Epoch != b.pdr.Epoch {
			return a.pdr.Epoch > b.pdr.Epoch
		}
		if ka, kb := a.shard.Key(), b.shard.Key(); ka != kb {
			return ka < kb
		}
		return a.hash < b.hash
	})
	if len(all) > maxKnownSaved {
		all = all[:maxKnownSaved]
	}
	out := make([]*types.PartitionDescriptionRecord, len(all))
	for i, e := range all {
		out[i] = e.pdr
	}
	f.saveMu.Lock()
	defer f.saveMu.Unlock()
	raw, err := json.Marshal(out)
	if err == nil {
		err = writeFileAtomic(path+".known", raw)
	}
	f.mu.Lock()
	f.knownDirty = err != nil // retried by the worker
	if err != nil {
		f.nextSave = f.now().Add(checkpointRetry)
	}
	f.mu.Unlock()
}

// retain marks a configuration a staged view needed: it is persisted first, whatever else the bound would drop.
func (f *shardConfFollower) retain(shard types.ShardID, hash []byte) {
	f.mu.Lock()
	k := shard.Key() + "/" + string(hash)
	changed := !f.retained[k]
	if f.retained == nil {
		f.retained = map[string]bool{}
	}
	f.retained[k] = true
	f.mu.Unlock()
	if changed {
		f.saveKnown()
	}
}

// restoreKnown reads the persisted configurations back.
func (f *shardConfFollower) restoreKnown(path string) {
	raw, err := os.ReadFile(path + ".known") // #nosec G304 -- operator supplied local file
	if err != nil {
		return
	}
	var all []*types.PartitionDescriptionRecord
	if json.Unmarshal(raw, &all) != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, pdr := range all {
		if pdr == nil || pdr.NetworkID != f.network || pdr.PartitionID != f.partition {
			continue
		}
		h, err := pdr.Hash(crypto.SHA256)
		if err != nil {
			continue
		}
		f.add(pdr.ShardID, h, pdr)
	}
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".shardconf-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
