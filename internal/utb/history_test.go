package utb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

// testdata/ucresp_v2_vectors.json is bft-core's (the entries, ids and genesis are what these tests use; the v2 response messages in it are superseded by the
// combined v3 response, whose vectors replace them when bft-core publishes them)  network/protocol/certification/testdata/ucresp_v2_vectors.json (UTB PR5), copied verbatim.
type vectors struct {
	Protocol         string   `json:"protocol"`
	GenesisEntry     string   `json:"genesisEntry"`
	GenesisEntryID   string   `json:"genesisEntryId"`
	Entries          []string `json:"entries"`  // epochs 2, 3, 4
	EntryIDs         []string `json:"entryIds"` // their EntryIDs
	AcceptedTwo      string   `json:"acceptedTwo"`
	RejectedOne      string   `json:"rejectedOne"`
	AcceptedNone     string   `json:"acceptedNone"`
	LegacyEquivalent string   `json:"legacyEquivalent"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ucresp_v2_vectors.json"))
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// entries are the fixture's entries [from, to) (epochs 2..4 are indexes 0..2) as the raw bytes a response attaches.
func entries(t *testing.T, v *vectors, from, to int) [][]byte {
	t.Helper()
	var out [][]byte
	for _, e := range v.Entries[from:to] {
		out = append(out, unhex(t, e))
	}
	return out
}

// historyAt opens an in-memory history holding the fixture's genesis plus the first n fixture entries.
func historyAt(t *testing.T, v *vectors, n int) *History {
	t.Helper()
	raw := [][]byte{unhex(t, v.GenesisEntry)}
	for _, e := range v.Entries[:n] {
		raw = append(raw, unhex(t, e))
	}
	return historyFromRaw(t, raw, v.GenesisEntryID)
}

func historyFromRaw(t *testing.T, raw [][]byte, pinHex string) *History {
	t.Helper()
	file, err := gettrustbase.EncodeBundle(raw)
	require.NoError(t, err)
	bundle, err := gettrustbase.DecodeBundle(file, gettrustbase.BundleLimits{MaxBytes: maxBundleBytes, MaxEntries: maxBundleEntries})
	require.NoError(t, err)
	pin, err := ParsePin(pinHex)
	require.NoError(t, err)
	require.NoError(t, gettrustbase.VerifyBundle(bundle, pin))
	h, err := open(memorydb.New(), bundle, pin)
	require.NoError(t, err)
	return h
}

// (2) the entries of epochs 2 and 3 authenticate from the pinned genesis and become the held history.
func TestVectorsAcceptedTwoAppendsFromGenesis(t *testing.T) {
	v := loadVectors(t)
	h := historyAt(t, v, 0)
	added, gap, err := h.Ingest(entries(t, v, 0, 2))
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 2, added)
	tip := h.Tip()
	require.Equal(t, uint64(3), tip.Epoch)
	require.Equal(t, v.EntryIDs[1], hex.EncodeToString(tip.EntryID[:]))
	for i, e := range v.Entries[:2] {
		got, err := h.store.Get(uint64(2 + i))
		require.NoError(t, err)
		require.Equal(t, unhex(t, e), got) // the stored bytes are the attached canonical bytes
	}
	// a replay is idempotent, and nothing is added by a response without entries
	added, gap, err = h.Ingest(entries(t, v, 0, 2))
	require.NoError(t, err)
	require.False(t, gap)
	require.Zero(t, added)
	added, _, err = h.Ingest(nil) // a response without entries
	require.NoError(t, err)
	require.Zero(t, added)
}

// (3) epoch 4 does not follow the genesis: it is not accepted, and the missing range is fetched (GetTrustBase) and authenticated entry by entry.
func TestVectorsGapAsksForTheRangeAndCatchesUp(t *testing.T) {
	v := loadVectors(t)
	h := historyAt(t, v, 0)
	added, gap, err := h.Ingest(entries(t, v, 2, 3))
	require.NoError(t, err)
	require.True(t, gap)
	require.Zero(t, added)
	require.Equal(t, uint64(1), h.Tip().Epoch)

	root := historyAt(t, v, 3) // a root that holds epochs 1..4
	srv, err := gettrustbase.NewServer(root.Source(), gettrustbase.Config{})
	require.NoError(t, err)
	n, err := h.CatchUpTo(context.Background(), &utbtest.Fetcher{Srv: srv}, []peer.ID{"root"}, 4)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	tip := h.Tip()
	require.Equal(t, uint64(4), tip.Epoch)
	require.Equal(t, v.EntryIDs[2], hex.EncodeToString(tip.EntryID[:]))
}

// (4) an entry attached to a rejected response is an authority update like any other: it is appended, and the response's status stays its own.
func TestRejectionsEntryIsAppendedAndTheStatusIsNotTouched(t *testing.T) {
	v := loadVectors(t)
	h := historyAt(t, v, 2)
	added, gap, err := h.Ingest(entries(t, v, 2, 3))
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 1, added)
	require.Equal(t, uint64(4), h.Tip().Epoch)
	rejected := &certification.CertificationResponse{Status: certification.CertStatusRequestInvalid}
	require.False(t, rejected.IsAccepted())
}

// A conflicting record for a held epoch is refused and the held one stays; an entry with a broken signature never enters.
func TestIngestRefusesConflictsAndBadSignatures(t *testing.T) {
	v := loadVectors(t)
	h := historyAt(t, v, 1)

	other, err := types.DecodeRootTrustBaseV2(unhex(t, v.Entries[0]))
	require.NoError(t, err)
	other.EpochStart++ // different unsigned bytes for held epoch 2
	raw, err := other.MarshalCBOR()
	require.NoError(t, err)
	_, _, err = h.Ingest([][]byte{raw})
	require.ErrorIs(t, err, utbstore.ErrConflict)
	held, err := h.store.Get(2)
	require.NoError(t, err)
	require.Equal(t, unhex(t, v.Entries[0]), held)

	next, err := types.DecodeRootTrustBaseV2(unhex(t, v.Entries[1]))
	require.NoError(t, err)
	for id, sig := range next.Signatures {
		bad := append([]byte(nil), sig...)
		bad[5] ^= 1
		next.Signatures[id] = bad
		break
	}
	raw, err = next.MarshalCBOR()
	require.NoError(t, err)
	_, _, err = h.Ingest([][]byte{raw})
	require.ErrorIs(t, err, utbstore.ErrEntry)
	require.Equal(t, uint64(2), h.Tip().Epoch)
}

// An older shipped history never rolls the store back, and a store rooted in another genesis is refused.
func TestOpenInstallsTheShippedHistoryAppendOnly(t *testing.T) {
	v := loadVectors(t)
	dir := t.TempDir()
	write := func(name string, raw [][]byte) string {
		file, err := gettrustbase.EncodeBundle(raw)
		require.NoError(t, err)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, file, 0o600))
		return p
	}
	g := unhex(t, v.GenesisEntry)
	full := write("full.cbor", [][]byte{g, unhex(t, v.Entries[0]), unhex(t, v.Entries[1])})
	db := filepath.Join(dir, "utb.db")

	h, err := Open(full, "", "0x"+v.GenesisEntryID, db)
	require.NoError(t, err)
	require.Equal(t, uint64(3), h.Tip().Epoch)
	require.NoError(t, h.Close())

	genesisFile := filepath.Join(dir, "genesis.cbor")
	require.NoError(t, os.WriteFile(genesisFile, g, 0o600))
	h, err = Open("", genesisFile, "0x"+v.GenesisEntryID, db) // restart with the genesis alone: the store keeps its tip
	require.NoError(t, err)
	require.Equal(t, uint64(3), h.Tip().Epoch)
	require.NoError(t, h.Close())

	_, err = Open("", genesisFile, "0x"+v.EntryIDs[0], filepath.Join(dir, "other.db"))
	require.Error(t, err) // the genesis is not the pinned identity
	_, err = Open(full, genesisFile, "0x"+v.GenesisEntryID, db)
	require.Error(t, err)
}
