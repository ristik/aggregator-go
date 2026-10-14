package utb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utbstore"
	"github.com/unicitynetwork/bft-go-base/types"
	bfthex "github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/aggregator-go/internal/utb/utbtest"
)

// testdata/ucresp_v2_vectors.json is bft-core's network/protocol/certification/testdata/ucresp_v2_vectors.json (UTB PR5), copied verbatim.
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

func decodeV2(t *testing.T, s string) *certification.CertificationResponseV2 {
	t.Helper()
	var cr certification.CertificationResponseV2
	require.NoError(t, types.Cbor.Unmarshal(unhex(t, s), &cr))
	require.NoError(t, cr.IsValid())
	return &cr
}

func updates(cr *certification.CertificationResponseV2) [][]byte {
	out := make([][]byte, len(cr.TrustBaseUpdates))
	for i, u := range cr.TrustBaseUpdates {
		out[i] = u
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

// (1) every message decodes strictly on the protocol the aggregator registers and re-encodes byte for byte.
func TestVectorsDecodeAndReencode(t *testing.T) {
	v := loadVectors(t)
	require.Equal(t, network.ProtocolUnicityCertificatesV2, v.Protocol)
	for name, msg := range map[string]string{"acceptedTwo": v.AcceptedTwo, "rejectedOne": v.RejectedOne, "acceptedNone": v.AcceptedNone} {
		cr := decodeV2(t, msg)
		again, err := types.Cbor.Marshal(cr)
		require.NoError(t, err, name)
		require.Equal(t, unhex(t, msg), again, name)
	}
	var legacy certification.CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(unhex(t, v.LegacyEquivalent), &legacy))
	again, err := types.Cbor.Marshal(&legacy)
	require.NoError(t, err)
	require.Equal(t, unhex(t, v.LegacyEquivalent), again)
	// the versions never cross: a version 2 reader refuses the legacy array
	var cr certification.CertificationResponseV2
	require.Error(t, types.Cbor.Unmarshal(unhex(t, v.LegacyEquivalent), &cr))
	require.Equal(t, decodeV2(t, v.AcceptedTwo).Response().UC, legacy.UC)
}

// (2) the entries of epochs 2 and 3 authenticate from the pinned genesis and become the held history.
func TestVectorsAcceptedTwoAppendsFromGenesis(t *testing.T) {
	v := loadVectors(t)
	h := historyAt(t, v, 0)
	added, gap, err := h.Ingest(updates(decodeV2(t, v.AcceptedTwo)))
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
	added, gap, err = h.Ingest(updates(decodeV2(t, v.AcceptedTwo)))
	require.NoError(t, err)
	require.False(t, gap)
	require.Zero(t, added)
	added, _, err = h.Ingest(updates(decodeV2(t, v.AcceptedNone)))
	require.NoError(t, err)
	require.Zero(t, added)
}

// (3) epoch 4 does not follow the genesis: it is not accepted, and the missing range is fetched (GetTrustBase) and authenticated entry by entry.
func TestVectorsGapAsksForTheRangeAndCatchesUp(t *testing.T) {
	v := loadVectors(t)
	h := historyAt(t, v, 0)
	added, gap, err := h.Ingest(updates(decodeV2(t, v.RejectedOne)))
	require.NoError(t, err)
	require.True(t, gap)
	require.Zero(t, added)
	require.Equal(t, uint64(1), h.Tip().Epoch)

	root := historyAt(t, v, 3) // a root that holds epochs 1..4
	srv, err := gettrustbase.NewServer(root.Source(), gettrustbase.Config{})
	require.NoError(t, err)
	n, err := h.CatchUp(context.Background(), &utbtest.Fetcher{Srv: srv}, []peer.ID{"root"})
	require.NoError(t, err)
	require.Equal(t, 3, n)
	tip := h.Tip()
	require.Equal(t, uint64(4), tip.Epoch)
	require.Equal(t, v.EntryIDs[2], hex.EncodeToString(tip.EntryID[:]))
}

// (4) the rejected message keeps its status: its valid entry is appended as an authority update, while the response stays a rejection.
func TestVectorsRejectionStaysARejection(t *testing.T) {
	v := loadVectors(t)
	cr := decodeV2(t, v.RejectedOne)
	require.False(t, cr.Response().IsAccepted())
	require.Equal(t, certification.CertStatusRequestInvalid, cr.Response().Status)
	require.True(t, decodeV2(t, v.AcceptedTwo).Response().IsAccepted())

	h := historyAt(t, v, 2)
	added, gap, err := h.Ingest(updates(cr))
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 1, added)
	require.Equal(t, uint64(4), h.Tip().Epoch)
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

func TestVerifyUCUnderItsOwnEpoch(t *testing.T) {
	const net types.NetworkID = 5
	k := utbtest.NewMembers(t, 4) // epoch 1 committee, threshold 3
	j := utbtest.NewMembers(t, 4) // epoch 2 committee
	outsider := utbtest.NewMembers(t, 1)[0]
	g := utbtest.Entry(t, net, 1, 1, k, nil, nil)
	e2 := utbtest.Entry(t, net, 2, 100, j, g, k[:3])
	graw, err := g.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	h := historyFromRaw(t, [][]byte{graw}, hex.EncodeToString(gid[:]))
	verify := func(uc *types.UnicityCertificate) error { return h.VerifyUC(uc, utbtest.Partition, types.ShardID{}) }

	require.NoError(t, verify(utbtest.Certificate(t, net, 1, 50, k[:3])))
	require.NoError(t, verify(utbtest.Certificate(t, net, 1, 150, k[:3]))) // the newest held epoch accepts rounds >= its start until its successor is held
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 2, 150, j[:3])), ErrUnknownEpoch)

	raw2, err := e2.MarshalCBOR()
	require.NoError(t, err)
	added, gap, err := h.Ingest([][]byte{raw2})
	require.NoError(t, err)
	require.False(t, gap)
	require.Equal(t, 1, added)

	require.NoError(t, verify(utbtest.Certificate(t, net, 1, 50, k[:3])))                                      // a historical certificate verifies with its own committee
	require.NoError(t, verify(utbtest.Certificate(t, net, 2, 150, j[:3])))                                     // the new epoch with the new committee
	require.NoError(t, verify(utbtest.Certificate(t, net, 2, 100, j)))                                         // at the new start, all signers
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 1, 100, k[:3])), ErrCertificate)                     // the retired committee after its successor started
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 2, 150, k[:3])), ErrCertificate)                     // the old committee signing the new epoch
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 2, 99, j[:3])), ErrCertificate)                      // before the epoch's start
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 2, 150, j[:2])), ErrCertificate)                     // below the weighted threshold
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 2, 150, append(j[:3:3], outsider))), ErrCertificate) // strict: an unknown signer fails
	require.ErrorIs(t, verify(utbtest.Certificate(t, net+1, 2, 150, j[:3])), ErrCertificate)                   // another network
	require.ErrorIs(t, verify(utbtest.Certificate(t, net, 3, 500, j[:3])), ErrUnknownEpoch)

	uc := utbtest.Certificate(t, net, 2, 150, j[:3]) // a broken signature among valid ones fails the whole check
	for id, sig := range uc.UnicitySeal.Signatures {
		bad := append(bfthex.Bytes(nil), sig...)
		bad[3] ^= 1
		uc.UnicitySeal.Signatures[id] = bad
		break
	}
	require.ErrorIs(t, verify(uc), ErrCertificate)

	// the version 1 provider path is closed: no projection is ever handed out as a trust base
	_, err = h.GetByEpoch(context.Background(), 1)
	require.True(t, errors.Is(err, errNoV1))
}
