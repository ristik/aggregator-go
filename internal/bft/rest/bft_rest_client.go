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

// ShardConfig asks the root for the configuration of one epoch of a shard (POST /api/v1/q3/shard-conf, the shard-aware read behind `ubft q3
// shard-conf`). That endpoint answers loopback peers only (the root's operator sources), so the aggregator reads it over the root's loopback RPC
// address, which it shares a network namespace with; there is deliberately no public variant. The answer is untrusted: the caller checks its
// hash against the one the root seal committed to. A configuration the root does not hold is (nil, nil).
func (c *BFTRestClient) ShardConfig(ctx context.Context, partition types.PartitionID, shard types.ShardID, epoch uint64) (*types.PartitionDescriptionRecord, error) {
	req := struct {
		Partition uint32 `json:"partition"`
		Shard     string `json:"shard,omitempty"`
		Epoch     uint64 `json:"epoch"`
	}{Partition: uint32(partition), Epoch: epoch}
	if shard.Length() > 0 {
		text, err := shard.MarshalText()
		if err != nil {
			return nil, err
		}
		req.Shard = string(text)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/q3/shard-conf", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return nil, nil // the endpoint's answer for a configuration it does not hold
	}
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
