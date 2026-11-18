package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"
)

type BFTRestClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewBFTRestClient(baseURL string) *BFTRestClient {
	return &BFTRestClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type GetTrustBasesResponse struct {
	_          struct{}                 `cbor:",toarray"`
	TrustBases []*types.RootTrustBaseV1 `cbor:"trustBases"`
}

func (c *BFTRestClient) GetTrustBases(ctx context.Context, fromEpoch, toEpoch uint64) ([]*types.RootTrustBaseV1, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/trustbases")
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	q := u.Query()
	q.Set("from", strconv.FormatUint(fromEpoch, 10))
	q.Set("to", strconv.FormatUint(toEpoch, 10))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/cbor")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	var response GetTrustBasesResponse
	if err := types.Cbor.GetDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR response: %w", err)
	}
	return response.TrustBases, nil
}

// ShardConfig asks the root for the configuration of a shard epoch of the (unsplit) shard of a partition (POST /api/v1/q3/shard-conf, the
// endpoint behind `ubft q3 shard-conf`). The answer is untrusted: the caller checks its hash against the one the root seal committed to.
func (c *BFTRestClient) ShardConfig(ctx context.Context, partition types.PartitionID, epoch uint64) (*types.PartitionDescriptionRecord, error) {
	body, err := json.Marshal(struct {
		Partition uint32 `json:"partition"`
		Epoch     uint64 `json:"epoch"`
	}{uint32(partition), epoch})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/q3/shard-conf", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var pdr types.PartitionDescriptionRecord
	if err := json.Unmarshal(raw, &pdr); err != nil {
		return nil, fmt.Errorf("decoding the shard configuration: %w", err)
	}
	return &pdr, nil
}
