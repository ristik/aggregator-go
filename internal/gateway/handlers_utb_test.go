package gateway

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/config"
	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/storage/interfaces"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb"
	"github.com/unicitynetwork/aggregator-go/internal/trustbase/utb/utbtest"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// utbService is the part of the service the trust-base routes and the health check use.
type utbService struct {
	Service
	latest *types.RootTrustBaseV1
	v1     []*types.RootTrustBaseV1
}

func (s *utbService) GetLatestTrustBase(context.Context) (*types.RootTrustBaseV1, error) {
	if s.latest == nil {
		return nil, interfaces.ErrTrustBaseNotFound
	}
	return s.latest, nil
}

func (s *utbService) GetTrustBases(context.Context, uint64, uint64) ([]*types.RootTrustBaseV1, error) {
	return s.v1, nil
}

func (s *utbService) GetHealthStatus(context.Context) (*api.HealthStatus, error) {
	return api.NewHealthStatus(api.HealthRoleStandalone, "test"), nil
}

type utbFixture struct {
	srv   *Server
	svc   *utbService
	chain *utbtest.Chain
	hist  *utb.History
}

func newUTBFixture(t *testing.T, cors bool, members, epochs, file int) *utbFixture {
	t.Helper()
	log, err := logger.New("error", "text", "stdout", false)
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server = config.ServerConfig{ConcurrencyLimit: 10, EnableCORS: cors}
	cfg.Sharding.Mode = config.ShardingModeStandalone
	chain := utbtest.NewChain(t, members, epochs, 0)
	hist, err := utb.Load(utb.LoadConfig{Path: utbtest.WriteFile(t, "b.cbor", chain.Bundle(t, file)), Pin: chain.Pin(t), Network: utbtest.Network})
	require.NoError(t, err)
	svc := &utbService{}
	srv := NewServer(cfg, log, svc)
	srv.SetTrustBaseHistory(utb.NewGuard(hist, svc.GetLatestTrustBase))
	return &utbFixture{srv: srv, svc: svc, chain: chain, hist: hist}
}

func (f *utbFixture) do(method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func (f *utbFixture) page(t *testing.T, target string) (*types.TrustBaseResponse, []*types.RootTrustBaseV2) {
	t.Helper()
	rec := f.do(http.MethodGet, target)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/cbor", rec.Header().Get("Content-Type"))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	r, es, err := types.DecodeTrustBaseResponse(rec.Body.Bytes(), types.TrustBasePageLimits)
	require.NoError(t, err)
	return r, es
}

func TestTheTrustBaseRouteServesTheHistoryAsTheSharedResponse(t *testing.T) {
	f := newUTBFixture(t, false, 4, 7, 7)

	r, es := f.page(t, "/api/v1/trustbases")
	require.Equal(t, types.TrustBaseStatusOK, r.Status)
	require.Equal(t, utbtest.Network, r.Network)
	require.Len(t, es, 7, "from defaults to the genesis epoch, to to the tip")
	for i, raw := range r.Entries {
		require.Equal(t, f.chain.Raw[i], []byte(raw), "entries are the stored bytes, verbatim")
	}

	id4 := f.chain.ID(t, 4)
	r, es = f.page(t, "/api/v1/trustbases?from=2&to=4")
	require.Len(t, es, 3)
	require.Equal(t, uint64(4), r.EffectiveEnd)
	require.Equal(t, id4[:], r.EndEntryID)

	r, _ = f.page(t, "/api/v1/trustbases?from=8")
	require.Equal(t, types.TrustBaseStatusNotYetAvailable, r.Status, "past the tip is a status, not an error")
	require.Equal(t, uint64(7), r.EffectiveEnd)

	r, _ = f.page(t, "/api/v1/trustbases?from=0")
	require.Equal(t, types.TrustBaseStatusInvalidRequest, r.Status)
}

func TestPagingOverHTTPFollowsTheSnapshot(t *testing.T) {
	f := newUTBFixture(t, false, 4, 9, 9)
	var epochs []uint64
	target := "/api/v1/trustbases?maxEntries=4"
	for pages := 0; ; pages++ {
		require.Less(t, pages, 4, "no progress")
		r, es := f.page(t, target)
		for _, e := range es {
			epochs = append(epochs, e.Epoch)
		}
		if r.NextEpoch == nil {
			break
		}
		target = "/api/v1/trustbases?maxEntries=4&from=" + strconv.FormatUint(*r.NextEpoch, 10) +
			"&snapshotEnd=" + strconv.FormatUint(r.EffectiveEnd, 10) + "&snapshotEntryId=0x" + hex.EncodeToString(r.EndEntryID)
	}
	require.Equal(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}, epochs)

	// a snapshot id of another history is a status in the response, not an HTTP error
	r, _ := f.page(t, "/api/v1/trustbases?from=2&snapshotEnd=9&snapshotEntryId=0x"+strings.Repeat("ab", 32))
	require.Equal(t, types.TrustBaseStatusHistoryMismatch, r.Status)
}

func TestAMalformedQueryIsA400AndNothingElseIs(t *testing.T) {
	f := newUTBFixture(t, true, 4, 3, 3)
	id := f.chain.ID(t, 3)
	idHex := "0x" + hex.EncodeToString(id[:])
	for name, target := range map[string]string{
		"from not a number":        "/api/v1/trustbases?from=abc",
		"from negative":            "/api/v1/trustbases?from=-1",
		"from overflows":           "/api/v1/trustbases?from=18446744073709551616",
		"from with a leading zero": "/api/v1/trustbases?from=01",
		"to not a number":          "/api/v1/trustbases?to=x",
		"from repeated":            "/api/v1/trustbases?from=1&from=2",
		"snapshotEnd alone":        "/api/v1/trustbases?snapshotEnd=3",
		"snapshotEntryId alone":    "/api/v1/trustbases?snapshotEntryId=" + idHex,
		"snapshot id not hex":      "/api/v1/trustbases?snapshotEnd=3&snapshotEntryId=0xzz",
		"snapshot id too short":    "/api/v1/trustbases?snapshotEnd=3&snapshotEntryId=0x1234",
		"maxEntries 0":             "/api/v1/trustbases?maxEntries=0",
		"maxEntries 65":            "/api/v1/trustbases?maxEntries=65",
		"maxEntries not a number":  "/api/v1/trustbases?maxEntries=many",
		"query too long":           "/api/v1/trustbases?x=" + strings.Repeat("a", 2000),
		"bad escape":               "/api/v1/trustbases?from=%zz",
	} {
		rec := f.do(http.MethodGet, target)
		require.Equal(t, http.StatusBadRequest, rec.Code, name)
		requireCORS(t, rec.Header()) // an error response is readable by a browser too
	}
	// unknown fields are ignored, a well-formed snapshot is fine
	require.Equal(t, http.StatusOK, f.do(http.MethodGet, "/api/v1/trustbases?future=1&snapshotEnd=3&snapshotEntryId="+idHex+"&from=1").Code)
}

func TestCORSOnTheTrustBaseRoute(t *testing.T) {
	on := newUTBFixture(t, true, 4, 3, 3)
	rec := on.do(http.MethodOptions, "/api/v1/trustbases")
	require.Equal(t, http.StatusOK, rec.Code)
	requireCORS(t, rec.Header())
	require.Equal(t, "GET, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"), "PUT is not advertised")
	rec = on.do(http.MethodGet, "/api/v1/trustbases")
	requireCORS(t, rec.Header())
	require.Equal(t, "GET, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
	// the degraded answer carries them as well
	on.svc.latest = on.chain.V1(3)
	on.svc.latest.EpochStart++
	requireCORS(t, on.do(http.MethodGet, "/api/v1/trustbases").Header())

	off := newUTBFixture(t, false, 4, 3, 3)
	for _, m := range []string{http.MethodGet, http.MethodOptions} {
		rec := off.do(m, "/api/v1/trustbases")
		require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"), m)
	}
}

func TestPutStaysAsItWasAndTheFileDoesNotFollowIt(t *testing.T) {
	f := newUTBFixture(t, false, 4, 4, 3) // the file stops at epoch 3 while the chain goes on
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/trustbases", strings.NewReader("{")))
	require.Equal(t, http.StatusBadRequest, rec.Code, "the V1 PUT handler still answers (malformed body)")

	// the aggregator's active authority moves to epoch 4 (PUT or the BFT admission): the file cannot follow
	f.svc.latest = f.chain.V1(4)
	r, _ := f.page(t, "/api/v1/trustbases")
	require.Equal(t, types.TrustBaseStatusUnavailable, r.Status, "not served while it disagrees with the active authority")
	require.Empty(t, r.Entries)

	health := f.do(http.MethodGet, "/health")
	require.Equal(t, http.StatusOK, health.Code)
	require.Contains(t, health.Body.String(), `"status":"degraded"`)
	require.Contains(t, health.Body.String(), "trustBaseV2Tip")

	// an authority the file covers is served again
	f.svc.latest = f.chain.V1(3)
	r, es := f.page(t, "/api/v1/trustbases")
	require.Equal(t, types.TrustBaseStatusOK, r.Status)
	require.Len(t, es, 3)
	health = f.do(http.MethodGet, "/health")
	require.Contains(t, health.Body.String(), `"status":"ok"`)
	require.Contains(t, health.Body.String(), "epoch 3 entry 0x")
}

func TestWithoutAHistoryTheRouteIsTheV1Route(t *testing.T) {
	log, err := logger.New("error", "text", "stdout", false)
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server = config.ServerConfig{ConcurrencyLimit: 10, EnableCORS: true}
	cfg.Sharding.Mode = config.ShardingModeStandalone
	chain := utbtest.NewChain(t, 4, 2, 0)
	svc := &utbService{latest: chain.V1(2), v1: []*types.RootTrustBaseV1{chain.V1(2)}}
	srv := NewServer(cfg, log, svc)

	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/trustbases", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var v1 TrustBasesResponse
	require.NoError(t, types.Cbor.Unmarshal(rec.Body.Bytes(), &v1), "the V1 response shape")
	require.Len(t, v1.TrustBases, 1)
	require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"), "no CORS on the V1 route")
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/api/v1/trustbases", nil))
	require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.NotContains(t, rec.Body.String(), "trustBaseV2")
}

func TestParseTrustBaseQueryDefaults(t *testing.T) {
	q, err := parseTrustBaseQuery(&url.URL{}, 5)
	require.NoError(t, err)
	require.Equal(t, utb.Query{From: 5, MaxEntries: 64}, q)
}
