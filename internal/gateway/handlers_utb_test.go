package gateway

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/gettrustbase"

	"github.com/unicitynetwork/aggregator-go/internal/config"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/utb"
)

// history opens a signed trust-base history holding the bft-core PR5 fixture chain (epochs 1..4).
func history(t *testing.T) (*utb.History, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "utb", "testdata", "ucresp_v2_vectors.json"))
	require.NoError(t, err)
	var v struct {
		GenesisEntry   string   `json:"genesisEntry"`
		GenesisEntryID string   `json:"genesisEntryId"`
		Entries        []string `json:"entries"`
		EntryIDs       []string `json:"entryIds"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	var entries [][]byte
	for _, s := range append([]string{v.GenesisEntry}, v.Entries...) {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		entries = append(entries, b)
	}
	file, err := gettrustbase.EncodeBundle(entries)
	require.NoError(t, err)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.cbor")
	require.NoError(t, os.WriteFile(bundle, file, 0o600))
	h, err := utb.Open(bundle, "", "0x"+v.GenesisEntryID, filepath.Join(dir, "utb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	hexEntries := append([]string{v.GenesisEntry}, v.Entries...)
	return h, hexEntries
}

func TestTrustBaseHistoryRange(t *testing.T) {
	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	h, entries := history(t)
	srv, err := gettrustbase.NewServer(h.Source(), gettrustbase.Config{})
	require.NoError(t, err)
	hf := getTrustBaseHistoryHandler(log, srv, h.Network(), h.GenesisEpoch())

	get := func(query string) *gettrustbase.Response {
		t.Helper()
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases"+query)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "application/cbor", res.Header.Get("Content-Type"))
		resp, _, err := gettrustbase.DecodeResponse(body, gettrustbase.PageLimits) // the PR6 codec, strictly
		require.NoError(t, err)
		return resp
	}

	all := get("") // from the genesis
	require.Equal(t, gettrustbase.StatusOK, all.Status)
	require.Len(t, all.Entries, 4)
	for i, e := range all.Entries {
		require.Equal(t, entries[i], hex.EncodeToString(e)) // the stored signed bytes, verbatim
	}
	require.Nil(t, all.NextEpoch)

	suffix := get("?from=3")
	require.Equal(t, uint64(3), suffix.FromEpoch)
	require.Equal(t, uint64(4), suffix.EffectiveEnd)
	require.Len(t, suffix.Entries, 2)

	page := get("?from=2&maxEntries=1")
	require.Len(t, page.Entries, 1)
	require.NotNil(t, page.NextEpoch)
	require.Equal(t, uint64(3), *page.NextEpoch)
	next := get(fmt.Sprintf("?from=3&maxEntries=1&snapshotEnd=%d&snapshotEntryId=0x%x", page.EffectiveEnd, page.EndEntryID))
	require.Equal(t, gettrustbase.StatusOK, next.Status)
	require.Equal(t, entries[2], hex.EncodeToString(next.Entries[0]))

	require.Equal(t, gettrustbase.StatusNotYetAvailable, get("?from=5").Status)
	require.Equal(t, gettrustbase.StatusHistoryMismatch, get("?from=3&snapshotEnd=4&snapshotEntryId=0x"+fmt.Sprintf("%064x", 1)).Status)

	for _, q := range []string{"?from=x", "?to=-1", "?maxEntries=0", "?maxEntries=65", "?snapshotEntryId=zz"} {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases"+q)
		require.Equal(t, http.StatusBadRequest, res.StatusCode, q)
	}
}

// With the signed history the administrative PUT does not exist: entries enter only through the authenticated append path.
func TestTrustBaseHistoryHasNoPut(t *testing.T) {
	log, err := logger.New("warn", "text", "stdout", false)
	require.NoError(t, err)
	h, _ := history(t)
	srv, err := gettrustbase.NewServer(h.Source(), gettrustbase.Config{})
	require.NoError(t, err)
	cfg := &config.Config{}
	s := NewServer(cfg, log, nil, WithTrustBaseHistory(srv, h.Network(), h.GenesisEpoch()))

	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/trustbases", nil))
	require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code)

	rec = httptest.NewRecorder()
	s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/trustbases?from=4", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	resp, _, err := gettrustbase.DecodeResponse(rec.Body.Bytes(), gettrustbase.PageLimits)
	require.NoError(t, err)
	require.Len(t, resp.Entries, 1)
}
