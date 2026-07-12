package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"

	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"
)

// hostRPC is the JSON-RPC transport that has no network. It satisfies solana-go's JSONRPCClient,
// so rpc.NewWithCustomRPCClient wraps it into the ordinary *rpc.Client the engine already takes
// and not one line of the reviewed engine changes. Instead of dialing an endpoint, each call
// marshals its request, hands the bytes to the driver (flynn core) as a FetchRequest, and blocks
// until core returns the response body.
//
// This is what lets the extension process run with egress fully denied on every platform: it has
// no socket, no endpoint, and no way to name one. A compromised extension can still ask core to
// send bytes, but only to the single endpoint core itself holds, so there is no address it can
// exfiltrate to and no internal service it can reach.
type hostRPC struct {
	reqCh chan<- HostCall
	repCh <-chan HostReply
	id    atomic.Uint64
}

// CallForInto sends one JSON-RPC request through the host and decodes the result into out. It
// is the only method the engine's six RPC calls reach, and it mirrors solana-go's own client:
// a JSON-RPC error from the node is returned as that error, so the engine's failure paths see
// exactly what they would over a direct connection.
func (h *hostRPC) CallForInto(ctx context.Context, out any, method string, params []any) error {
	// The id only has to be unique within this session's requests, and the response is read
	// positionally (one request, one response), so it is masked into a positive int rather than
	// widened: a counter that wrapped would still be a valid JSON-RPC id.
	req := jsonrpc.RPCRequest{
		ID:      int(h.id.Add(1) & math.MaxInt32),
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("token: marshal %s request: %w", method, err)
	}

	res, err := h.roundTrip(ctx, body)
	if err != nil {
		return fmt.Errorf("token: %s through the host: %w", method, err)
	}

	var reply jsonrpc.RPCResponse
	if err := json.Unmarshal(res, &reply); err != nil {
		return fmt.Errorf("token: decode %s response: %w", method, err)
	}
	if reply.Error != nil {
		return reply.Error
	}
	return reply.GetObject(out)
}

// roundTrip hands one request body to the driver and blocks for the response. The context is
// honoured while waiting so a cancelled lifecycle unwinds instead of parking forever on the
// channel: the session cancels its context on Close, and the engine's own deadlines flow
// through here.
func (h *hostRPC) roundTrip(ctx context.Context, body []byte) ([]byte, error) {
	select {
	case h.reqCh <- HostCall{Fetch: &FetchRequest{Body: body}}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-h.repCh:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Body, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// errNoDirectTransport is returned for the two JSONRPCClient methods the engine never calls.
// They are refused rather than implemented over the host channel: batching and raw HTTP-response
// access are not part of the boundary this extension is allowed, and a silent fallback that
// reintroduced a direct connection is exactly the hole this transport exists to close.
var errNoDirectTransport = errors.New("token: this transport has no network; only single JSON-RPC calls cross the host boundary")

func (h *hostRPC) CallWithCallback(context.Context, string, []any, func(*http.Request, *http.Response) error) error {
	return errNoDirectTransport
}

func (h *hostRPC) CallBatch(context.Context, jsonrpc.RPCRequests) (jsonrpc.RPCResponses, error) {
	return nil, errNoDirectTransport
}

var _ rpc.JSONRPCClient = (*hostRPC)(nil)

// newHostClient builds the *rpc.Client the engine consumes, backed by the host transport.
func newHostClient(reqCh chan<- HostCall, repCh <-chan HostReply) *rpc.Client {
	return rpc.NewWithCustomRPCClient(&hostRPC{reqCh: reqCh, repCh: repCh})
}
