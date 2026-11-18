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
// hash to a configuration through a ShardConfSource (the root's loopback, guarded POST /api/v1/q3/shard-conf), requires the answer to hash to exactly the
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
	maxConfWaiters   = 16               // distinct deferred responses per lookup
	maxConfBacklog   = 256              // deferred responses charged at once: registered with a lookup or queued for handback, until actually handed back
	confPendingTTL   = 10 * time.Minute // a lookup unresolved for this long is obsolete (the shard moved on or the hash is not a configuration)
	checkpointRetry  = 30 * time.Second // between attempts to persist a checkpoint or the needed configurations that failed to save
)

// lookup is the single-flight resolution of one (shard, sealed hash). It owns the deferred responses that registered it until it completes
// or expires; both act on the lookup currently registered under its key, by identity.
type lookup struct {
	shard   types.ShardID
	sealed  []byte
	hints   []uint64
	fails   int
	next    time.Time
	born    time.Time
	local   bool  // the configuration of our own shard (current progress), served and admitted before a sibling's
	waiters []any // the deferred responses registered with it
}

// shardConfFollower resolves and holds the configurations of the shard (and, for the consolidation topology, of its siblings). One mutex
// guards the whole bookkeeping.
type shardConfFollower struct {
	source    ShardConfSource
	network   types.NetworkID
	partition types.PartitionID
	ours      types.ShardID
	now       func() time.Time

	mu      sync.Mutex
	known   map[string]map[string]*types.PartitionDescriptionRecord // shard key -> sealed hash -> configuration
	pending map[string]*lookup                                      // the registered lookups by shard key/hash
	ready   []any                                                   // resolved or obsolete lookups' responses, in order, charged until handed back
	latest  *types.PartitionDescriptionRecord                       // the published configuration of our shard
	needed  map[string][]byte                                       // the configuration hash of each shard in the latest staged view
	wake    chan struct{}
	// deliver hands a deferred response back to the message loop; it reports whether it was taken (the channel may be full)
	deliver func(any) bool

	flushMu sync.Mutex // one handback at a time: the head of ready is stable while it is offered
	// checkpoint is the file the published configuration is persisted in ("" none); unsaved is the checkpoint whose save failed, retried
	checkpoint string
	unsaved    *checkpointJob
	nextSave   time.Time  // the next attempt at the checkpoint
	nextKnown  time.Time  // the next attempt at the needed-configurations file: its own schedule, never delaying the checkpoint
	knownDirty bool       // the needed-configurations file failed to save
	saveMu     sync.Mutex // serializes the writers of the checkpoint and the needed-configurations file
}

type checkpointJob struct {
	pdr *types.PartitionDescriptionRecord
	uc  *types.UnicityCertificate
}

func newShardConfFollower(source ShardConfSource, start *types.PartitionDescriptionRecord, startHash []byte) *shardConfFollower {
	f := &shardConfFollower{source: source, network: start.NetworkID, partition: start.PartitionID, ours: start.ShardID, now: time.Now,
		known: map[string]map[string]*types.PartitionDescriptionRecord{}, pending: map[string]*lookup{}, needed: map[string][]byte{},
		wake: make(chan struct{}, 1), latest: start}
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
	confQueued  confResult = iota // the lookup is registered and the response (if any) is charged to it
	confKnown                     // the configuration is known already: nothing to defer
	confRefused                   // no capacity (lookups, waiters of the lookup, or the backlog): nothing was registered
)

// ErrShardConfBusy reports an authentic certificate (or view) that could not be deferred for lack of capacity: it is refused, not pending,
// and is reported; the root sends the certificate again (the inactivity recovery asks for it).
var ErrShardConfBusy = errors.New("shard configuration lookups are at capacity")

// backlogLocked is the budget in use: every response is charged from registration until it is actually handed back.
func (f *shardConfFollower) backlogLocked() int {
	n := len(f.ready)
	for _, l := range f.pending {
		n += len(l.waiters)
	}
	return n
}

// request registers the lookup of the sealed hash of a shard's configuration (single-flight: a lookup already registered is joined and only
// gains hints). hints are the shard epochs it can be, from authenticated records. waiter, when not nil, is the deferred response that needs
// the configuration: it is charged to the lookup before the worker is woken and stays charged until handed back.
func (f *shardConfFollower) request(shard types.ShardID, sealed []byte, hints []uint64, waiter any) confResult {
	f.mu.Lock()
	if _, ok := f.known[shard.Key()][string(sealed)]; ok {
		f.mu.Unlock()
		return confKnown
	}
	key := shard.Key() + "/" + string(sealed)
	now := f.now()
	f.expireLocked(now)
	l := f.pending[key]
	if l == nil {
		local := shard.Equal(f.ours)
		if len(f.pending) >= maxPendingConfs && !f.reclaimLocked(local) {
			f.mu.Unlock()
			return confRefused
		}
		l = &lookup{shard: shard, sealed: bytes.Clone(sealed), next: now, born: now, local: local}
	}
	if waiter != nil {
		wk := waiterKey(waiter)
		replaced := false
		for i, w := range l.waiters {
			if waiterKey(w) == wk { // the same response delivered again: it supplies the same certificate and sidecar
				l.waiters[i], replaced = waiter, true
				break
			}
		}
		if !replaced {
			if len(l.waiters) >= maxConfWaiters || f.backlogLocked() >= maxConfBacklog {
				f.mu.Unlock()
				return confRefused // nothing already charged is dropped; this delivery is refused and the caller reports it
			}
			l.waiters = append(l.waiters, waiter)
		}
	}
	for _, h := range hints {
		if len(l.hints) < maxConfHints && !containsEpoch(l.hints, h) {
			l.hints = append(l.hints, h)
		}
	}
	f.pending[key] = l
	due := !l.next.After(now)
	f.mu.Unlock()
	if due {
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
	return confQueued
}

// reclaimLocked makes room for the local shard's lookup by dropping the oldest sibling lookup that holds no response (one that holds a
// response is never dropped). Siblings never displace anything.
func (f *shardConfFollower) reclaimLocked(local bool) bool {
	if !local {
		return false
	}
	var oldest string
	var at time.Time
	for k, l := range f.pending {
		if !l.local && len(l.waiters) == 0 && (oldest == "" || l.born.Before(at)) {
			oldest, at = k, l.born
		}
	}
	if oldest == "" {
		return false
	}
	delete(f.pending, oldest)
	return true
}

// expireLocked drops the lookups that are obsolete; each hands its responses back (they verify again and queue a fresh lookup if still needed).
// It acts on the registered lookup it found, so a fresh lookup registered later under the same key is untouched.
func (f *shardConfFollower) expireLocked(now time.Time) {
	for k, l := range f.pending {
		if now.Sub(l.born) > confPendingTTL {
			f.ready = append(f.ready, l.waiters...)
			l.waiters = nil
			if f.pending[k] == l {
				delete(f.pending, k)
			}
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

// process hands back what is ready, retries failed saves and resolves every lookup that is due, the local shard's first.
func (f *shardConfFollower) process(ctx context.Context) {
	f.flush()
	f.retrySave()
	f.mu.Lock()
	f.expireLocked(f.now())
	var due []*lookup
	for _, l := range f.pending {
		if !l.next.After(f.now()) {
			due = append(due, l)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].local != due[j].local {
			return due[i].local
		}
		return due[i].born.Before(due[j].born)
	})
	f.mu.Unlock()
	for _, l := range due {
		if ctx.Err() != nil {
			return
		}
		f.resolve(ctx, l)
	}
	f.flush()
}

func (f *shardConfFollower) resolve(ctx context.Context, l *lookup) {
	ctx, cancel := context.WithTimeout(ctx, confFetchBudget)
	defer cancel()
	f.mu.Lock()
	hints := append([]uint64(nil), l.hints...)
	f.mu.Unlock()
	failed := false
	for _, epoch := range hints {
		pdr, err := f.source.ShardConfig(ctx, f.partition, l.shard, epoch)
		if err != nil {
			failed = true
			break // the source is failing: back off rather than spend the budget on the other hints
		}
		if pdr == nil {
			continue
		}
		h, err := pdr.Hash(crypto.SHA256)
		if err != nil || pdr.Epoch != epoch || pdr.NetworkID != f.network || pdr.PartitionID != f.partition || !pdr.ShardID.Equal(l.shard) || !bytes.Equal(h, l.sealed) {
			continue
		}
		f.complete(l, h, pdr)
		return
	}
	_ = failed
	f.mu.Lock()
	l.fails++
	back := confBackoffFirst << min(l.fails-1, 6)
	if back > confBackoffMax {
		back = confBackoffMax
	}
	l.next = f.now().Add(back)
	f.mu.Unlock()
}

// complete records a verified configuration and finishes the lookup registered under its key: the responses it holds move to the handback
// queue exactly once, under the mutex. The fetched lookup l may have expired and been replaced meanwhile; the configuration is valid either
// way, and the registered lookup's responses are the ones handed back.
func (f *shardConfFollower) complete(l *lookup, hash []byte, pdr *types.PartitionDescriptionRecord) {
	f.mu.Lock()
	f.add(l.shard, hash, pdr)
	key := l.shard.Key() + "/" + string(l.sealed)
	if cur := f.pending[key]; cur != nil {
		f.ready = append(f.ready, cur.waiters...)
		cur.waiters = nil
		delete(f.pending, key)
	}
	f.mu.Unlock()
	f.flush()
}

// flush hands the queued responses back to the message loop in order. A response stays queued, and charged, until it is taken: one that is
// not taken stays at the head in place and the pass stops.
func (f *shardConfFollower) flush() {
	f.flushMu.Lock()
	defer f.flushMu.Unlock()
	for {
		f.mu.Lock()
		deliver := f.deliver
		if deliver == nil || len(f.ready) == 0 {
			f.mu.Unlock()
			return
		}
		head := f.ready[0]
		f.mu.Unlock()
		if !deliver(head) {
			return
		}
		f.mu.Lock()
		f.ready = f.ready[1:] // only flush removes from the head, and flushMu serializes it
		f.mu.Unlock()
	}
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
	f.saveNeeded() // the published configuration is among what a restart needs
	return pdr, true, err
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

// retrySave retries what failed to save, the live checkpoint first; each file has its own retry schedule, so a failing cache file never
// delays the checkpoint.
func (f *shardConfFollower) retrySave() {
	f.mu.Lock()
	job, path, due := f.unsaved, f.checkpoint, !f.now().Before(f.nextSave)
	f.mu.Unlock()
	if job != nil && path != "" && due {
		err := f.writeCheckpoint(job)
		f.mu.Lock()
		if err != nil {
			f.nextSave = f.now().Add(checkpointRetry)
		} else if f.unsaved == job { // not replaced by a newer configuration meanwhile
			f.unsaved = nil
		}
		f.mu.Unlock()
	}
	f.mu.Lock()
	dirty, dueKnown := f.knownDirty, !f.now().Before(f.nextKnown)
	f.mu.Unlock()
	if dirty && dueKnown {
		f.saveNeeded()
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

// What a restart needs of the resolved configurations is persisted beside the checkpoint (<checkpoint>.known): the published configuration of
// our shard and, for each shard, the configuration the latest staged view committed to. The set is replaced as views advance, so it is as
// large as the view's shards and never accumulates history. The file is a cache: each entry is checked against its own hash and the shard
// identity when read, only widens which seal-authenticated leaf hashes a following pin accepts, and the leaf itself is authenticated by the seal.
func (f *shardConfFollower) saveNeeded() {
	f.saveMu.Lock() // the snapshot is taken under the writer lock: an older one cannot overtake a newer
	defer f.saveMu.Unlock()
	f.mu.Lock()
	path := f.checkpoint
	var out []*types.PartitionDescriptionRecord
	if h, err := f.latest.Hash(crypto.SHA256); err == nil {
		if pdr := f.known[f.ours.Key()][string(h)]; pdr != nil {
			out = append(out, pdr)
		}
	}
	keys := make([]string, 0, len(f.needed))
	for k := range f.needed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if pdr := f.known[k][string(f.needed[k])]; pdr != nil && !(len(out) > 0 && out[0] == pdr) {
			out = append(out, pdr)
		}
	}
	f.mu.Unlock()
	if path == "" {
		return
	}
	raw, err := json.Marshal(out)
	if err == nil {
		err = writeFileAtomic(path+".known", raw)
	}
	f.mu.Lock()
	f.knownDirty = err != nil // retried by the worker
	if err != nil {
		f.nextKnown = f.now().Add(checkpointRetry)
	}
	f.mu.Unlock()
}

// setNeeded records the configuration hash of each shard the latest staged view committed to (replacing the previous view's) and persists it.
func (f *shardConfFollower) setNeeded(view map[string][]byte) {
	f.mu.Lock()
	f.needed = view
	f.mu.Unlock()
	f.saveNeeded()
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
		f.needed[pdr.ShardID.Key()] = h // what the restart resumed from is what it needs until a newer view replaces it
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
