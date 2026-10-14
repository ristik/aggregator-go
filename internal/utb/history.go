// Package utb holds the aggregator's signed Unicity Trust Base history (record version 2) for a deployment whose roots publish signed entries.
//
// The history starts from the shipped tagged bundle (the complete history known at release time, authenticated from the pinned genesis EntryID) and
// grows only through the bft-core entry store's single append path: each new entry is verified strictly from the latest held entry (epoch+1, start,
// predecessor EntryID, the predecessor committee's strict weighted quorum over the unsigned bytes). Held entries are never replaced; a different record
// for a held epoch is a conflict. Entries arrive attached to certification responses or, for gaps, from the roots' GetTrustBase protocol.
//
// Each aggregator process keeps its own store (a local bolt file): nothing is shared or trusted between replicas, every replica authenticates the same
// entries itself.
package utb

import (
	"context"
	gocrypto "crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/utbstore"
)

var (
	// ErrUnknownEpoch: no held entry for the certificate's epoch; the caller catches up and retries, and nothing advances meanwhile.
	ErrUnknownEpoch = errors.New("utb: no held trust-base entry for the epoch")
	// ErrCertificate: the certificate does not verify under its own epoch's committee and activation interval.
	ErrCertificate = errors.New("utb: certificate refused")
)

// Bundle file budget (the page limits do not apply to the complete shipped history).
const (
	maxBundleBytes   = 64 << 20
	maxBundleEntries = 1 << 16
	catchUpTimeout   = 10 * time.Second
)

// History is safe for concurrent use.
type History struct {
	store   *utbstore.Store
	network types.NetworkID
	closeDB func() error

	syncMu sync.Mutex // one catch-up at a time
}

// Open loads the shipped history, checks it against the pin, opens (or creates) the local store rooted in its genesis and installs it through the
// append path: an older history never rolls the store back and a conflicting record is refused. The shipped history is either a complete tagged bundle
// (bundleFile) or, for a fresh chain, the canonical genesis entry alone (genesisFile).
func Open(bundleFile, genesisFile, pinHex, dbFile string) (*History, error) {
	pin, err := ParsePin(pinHex)
	if err != nil {
		return nil, err
	}
	var data []byte
	switch {
	case bundleFile != "" && genesisFile != "":
		return nil, errors.New("give either the trust-base bundle or the genesis entry, not both")
	case bundleFile != "":
		if data, err = os.ReadFile(bundleFile); err != nil {
			return nil, fmt.Errorf("reading the trust-base bundle: %w", err)
		}
	case genesisFile != "":
		raw, err := os.ReadFile(genesisFile)
		if err != nil {
			return nil, fmt.Errorf("reading the trust-base genesis entry: %w", err)
		}
		if data, err = gettrustbase.EncodeBundle([][]byte{raw}); err != nil {
			return nil, fmt.Errorf("the trust-base genesis entry: %w", err)
		}
	default:
		return nil, errors.New("a trust-base bundle or genesis entry is required")
	}
	bundle, err := gettrustbase.DecodeBundle(data, gettrustbase.BundleLimits{MaxBytes: maxBundleBytes, MaxEntries: maxBundleEntries})
	if err != nil {
		return nil, fmt.Errorf("decoding the trust-base bundle: %w", err)
	}
	if err := gettrustbase.VerifyBundle(bundle, pin); err != nil {
		return nil, fmt.Errorf("verifying the trust-base bundle: %w", err)
	}
	db, err := boltdb.New(dbFile)
	if err != nil {
		return nil, fmt.Errorf("opening the trust-base store %s: %w", dbFile, err)
	}
	h, err := open(db, bundle, pin)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	h.closeDB = db.Close
	return h, nil
}

func open(db keyvaluedb.KeyValueDB, bundle *gettrustbase.Bundle, pin [types.TrustBaseV2IDLen]byte) (*History, error) {
	store, err := utbstore.Open(db, bundle.Entries[0], pin)
	if err != nil {
		return nil, fmt.Errorf("opening the trust-base store: %w", err)
	}
	if _, err := gettrustbase.InstallBundle(store, bundle); err != nil {
		return nil, err
	}
	return &History{store: store, network: bundle.Network}, nil
}

// ParsePin reads the 0x-prefixed genesis EntryID.
func ParsePin(s string) ([types.TrustBaseV2IDLen]byte, error) {
	var pin [types.TrustBaseV2IDLen]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != len(pin) {
		return pin, fmt.Errorf("the trust-base genesis id must be a 0x-prefixed %d-byte hex string", len(pin))
	}
	copy(pin[:], b)
	return pin, nil
}

// Close releases the local store.
func (h *History) Close() error {
	if h.closeDB == nil {
		return nil
	}
	return h.closeDB()
}

// Network is the deployment's network identifier.
func (h *History) Network() types.NetworkID { return h.network }

// GenesisEpoch is the pinned genesis entry's epoch.
func (h *History) GenesisEpoch() uint64 { return h.store.GenesisEpoch() }

// Tip is the latest held entry.
func (h *History) Tip() utbstore.Tip { return h.store.Tip() }

// Committee is the held entry of an epoch: the committee that signs that epoch's certificates. It is an authority only for its own epoch; a held future
// entry does not mean its committee is reachable yet.
func (h *History) Committee(epoch uint64) (*types.RootTrustBaseV2, error) {
	e, err := h.store.Entry(epoch)
	if err != nil {
		return nil, fmt.Errorf("%w %d", ErrUnknownEpoch, epoch)
	}
	return e, nil
}

// Source is the store as the GetTrustBase serving contract sees it (stored canonical bytes only).
func (h *History) Source() gettrustbase.Source { return h.store }

// Ingest appends the entries attached to a certification response, in order. It returns the number appended and whether an entry did not follow the
// held tip (the caller then catches up). An entry that does not authenticate stops the update and is returned as an error; it never affects the
// certificate, which is judged separately.
func (h *History) Ingest(updates [][]byte) (added int, gap bool, err error) {
	for _, raw := range updates {
		isNew, err := h.store.Append(raw)
		switch {
		case err == nil:
			if isNew {
				added++
			}
		case errors.Is(err, utbstore.ErrGap):
			return added, true, nil
		default:
			return added, false, err
		}
	}
	return added, false, nil
}

// CatchUp fetches the missing suffix after the latest held entry from the given root peers (GetTrustBase), authenticating every entry from the one
// before it. Authenticated prefixes are kept when a later page fails.
func (h *History) CatchUp(ctx context.Context, f gettrustbase.Fetcher, peers []peer.ID) (int, error) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, catchUpTimeout)
	defer cancel()
	return gettrustbase.Sync(ctx, f, h.store, peers, gettrustbase.SyncOptions{Network: h.network})
}

// VerifyUC verifies a certificate under its own epoch: the held entry of the seal's epoch (strict weighted quorum, unknown or invalid signers fail), the
// network, and the epoch's activation interval (the seal round is not before the epoch's start and, once the successor is held, before the successor's
// start: a retired committee cannot certify rounds after its successor started). ErrUnknownEpoch means the authority is not known yet.
func (h *History) VerifyUC(uc *types.UnicityCertificate, partition types.PartitionID, shard types.ShardID) error {
	if uc == nil || uc.UnicitySeal == nil {
		return fmt.Errorf("%w: no seal", ErrCertificate)
	}
	seal := uc.UnicitySeal
	entry, err := h.Committee(seal.Epoch)
	if err != nil {
		return err
	}
	if seal.NetworkID != entry.NetworkID {
		return fmt.Errorf("%w: network %d, epoch %d belongs to network %d", ErrCertificate, seal.NetworkID, seal.Epoch, entry.NetworkID)
	}
	if seal.RootChainRoundNumber < entry.EpochStart {
		return fmt.Errorf("%w: root round %d precedes the start %d of epoch %d", ErrCertificate, seal.RootChainRoundNumber, entry.EpochStart, seal.Epoch)
	}
	if next, err := h.store.Entry(seal.Epoch + 1); err == nil && seal.RootChainRoundNumber >= next.EpochStart {
		return fmt.Errorf("%w: root round %d is at or after the start %d of epoch %d", ErrCertificate, seal.RootChainRoundNumber, next.EpochStart, next.Epoch)
	}
	if err := uc.Verify(entry, gocrypto.SHA256, partition, shard, nil); err != nil {
		return fmt.Errorf("%w: %w", ErrCertificate, err)
	}
	return nil
}

// errNoV1 is the answer to a version 1 trust-base request in a deployment with the signed history: a runtime projection is not a trust entry and is
// never handed out as one.
var errNoV1 = errors.New("utb: version 1 trust bases are not used with the signed trust-base history")

// GetByEpoch makes the history the BFT client's trust-base provider; the client uses UTBHistory and verifies every certificate from the signed entries.
func (h *History) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return nil, errNoV1
}

// UTBHistory is how the BFT client recognizes a provider with the signed history.
func (h *History) UTBHistory() *History { return h }
