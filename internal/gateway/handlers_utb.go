package gateway

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/logger"
)

// Option configures the gateway server.
type Option func(*Server)

// WithTrustBaseHistory serves the signed trust-base history (record version 2) on GET /api/v1/trustbases instead of the version 1 trust bases, and
// removes the PUT: entries enter only through the authenticated append path, never administratively.
func WithTrustBaseHistory(srv *gettrustbase.Server, network types.NetworkID, genesisEpoch uint64) Option {
	return func(s *Server) { s.utbServer, s.utbNetwork, s.utbGenesis = srv, network, genesisEpoch }
}

// getTrustBaseHistoryHandler answers a range of the retained signed entries with the GetTrustBase response codec (tagged CBOR, the same bytes a root
// peer would send): GET /api/v1/trustbases?from=E[&to=E][&snapshotEnd=E&snapshotEntryId=0x..][&maxEntries=N]. from defaults to the genesis epoch. It
// serves stored signed bytes only and says nothing about any token; the client authenticates the entries from its own latest held entry. The outcome
// (including NotYetAvailable or HistoryMismatch) is the status inside the response; a malformed query is 400.
func getTrustBaseHistoryHandler(logger *logger.Logger, srv *gettrustbase.Server, network types.NetworkID, genesisEpoch uint64) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		q := c.Request.URL.Query()
		req := &gettrustbase.Request{Version: gettrustbase.Version, Network: network,
			MaxEntries: gettrustbase.DefaultMaxEntries, MaxBytes: gettrustbase.DefaultMaxResponse}
		var err error
		if req.FromEpoch, err = parseUint64WithDefault(q, "from", genesisEpoch); err != nil {
			http.Error(c.Writer, err.Error(), http.StatusBadRequest)
			return
		}
		for _, p := range []struct {
			key string
			dst **uint64
		}{{"to", &req.ToEpoch}, {"snapshotEnd", &req.SnapshotEnd}} {
			if q.Get(p.key) == "" {
				continue
			}
			v, err := parseUint64WithDefault(q, p.key, 0)
			if err != nil {
				http.Error(c.Writer, err.Error(), http.StatusBadRequest)
				return
			}
			*p.dst = &v
		}
		if s := q.Get("snapshotEntryId"); s != "" {
			if req.SnapshotEntryID, err = hex.DecodeString(strings.TrimPrefix(s, "0x")); err != nil {
				http.Error(c.Writer, fmt.Sprintf("invalid snapshotEntryId: %v", err), http.StatusBadRequest)
				return
			}
		}
		if q.Get("maxEntries") != "" {
			n, err := parseUint64WithDefault(q, "maxEntries", 0)
			if err != nil || n == 0 || n > gettrustbase.DefaultMaxEntries {
				http.Error(c.Writer, fmt.Sprintf("maxEntries must be 1..%d", gettrustbase.DefaultMaxEntries), http.StatusBadRequest)
				return
			}
			req.MaxEntries = uint32(n)
		}
		resp := srv.Respond(req)
		logger.WithContext(ctx).Info("served trust-base history range", "from", req.FromEpoch, "status", resp.Status.String(),
			"entries", len(resp.Entries), "effectiveEnd", resp.EffectiveEnd, "remote", c.ClientIP())
		body, err := resp.Encode()
		if err != nil {
			logger.WithContext(ctx).Error("GET trustbases: encoding the response", "error", err.Error())
			http.Error(c.Writer, "failed to encode the response", http.StatusInternalServerError)
			return
		}
		c.Data(http.StatusOK, "application/cbor", body)
	}
}
