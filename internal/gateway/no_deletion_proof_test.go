package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

type noDeletionService struct {
	Service
	err error
}

func (n noDeletionService) GetNoDeletionProof(context.Context) (*api.GetNoDeletionProofResponse, error) {
	return nil, n.err
}

// get_no_deletion_proof is not implemented: it is answered as an unsupported method, never with a
// result a client could take for a proof.
func TestGetNoDeletionProofIsUnsupportedNotAFakeSuccess(t *testing.T) {
	unsupported := newRPCTestServer(t, noDeletionService{err: api.ErrNotSupported}, func(s *Server) {
		s.rpcServer.RegisterMethod("get_no_deletion_proof", s.handleGetNoDeletionProof)
	})
	code, body := postRPC(t, unsupported, `{"jsonrpc":"2.0","id":1,"method":"get_no_deletion_proof","params":{}}`)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, `"error"`)
	require.Contains(t, body, `-32601`)
	require.Contains(t, body, "not supported")
	require.NotContains(t, body, `"result"`)
	require.False(t, strings.Contains(body, "mock_no_deletion_proof"))

	// any other failure stays an internal error
	failing := newRPCTestServer(t, noDeletionService{err: context.DeadlineExceeded}, func(s *Server) {
		s.rpcServer.RegisterMethod("get_no_deletion_proof", s.handleGetNoDeletionProof)
	})
	_, body = postRPC(t, failing, `{"jsonrpc":"2.0","id":2,"method":"get_no_deletion_proof","params":{}}`)
	require.Contains(t, body, `-32603`)
}
