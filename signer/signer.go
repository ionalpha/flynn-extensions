// Package signer is the shared harness every chain signer is built from: key custody, the
// two MCP tools flynn speaks to, and the rule that a payload is parsed before it is signed.
//
// A signer extension exists to hold one chain's key and that chain's transaction parser,
// together, in a process that does nothing else. The reason they belong together is the whole
// architecture: whoever holds a key must understand what they are signing, or they sign blind.
// Flynn therefore holds no key and carries no parser; it routes opaque bytes to a signer and
// reads neither direction, which is what lets it stay a general engine while still refusing to
// sign a transaction that would drain you.
//
// The separation from the WORKER extension is the security property, and it is easy to throw
// away by accident. The worker (the token extension, say) builds the transaction. This signer
// holds the key and decides, independently, whether to sign it. They are different artifacts,
// published and pinned separately. A worker compromised upstream obtains no signature: it
// would have to compromise this signer too. If the parser is ever moved into the worker, the
// worker is vouching for its own payload, and the entire scheme collapses to blind signing.
//
// What is generic lives here: custody, curves, the protocol, the refusal. What is chain-
// specific is a Policy, and there is one per chain. A single "generic transaction validator"
// is not possible and must not be attempted: the rules do not translate (revoking a mint
// authority has no EVM analogue), so it would end up either loose enough to approve the
// transaction that drains you, or a pile of chain-specific branches pretending to be generic.
//
// One binary per chain, holding exactly one chain's key. A single signer holding every chain's
// keys would put the Solana key in the same process as an EVM parser bug.
package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ionalpha/flynn-extensions/mcpserver"
)

// Key is custody: the private half, wherever it actually lives. An implementation may hold the
// key in memory (unsealed from an encrypted store at startup) or front a hardware device that
// never surrenders it. The harness only ever asks it to sign, and never to hand the key over.
//
// Public returns raw bytes because a key sits on a curve and the curves differ: ed25519 for
// Solana, secp256k1 for EVM and Bitcoin. Nothing in this package interprets those bytes.
type Key interface {
	// Public is the public half, raw bytes.
	Public() []byte
	// Curve names the curve, for the operator's benefit. It is reported, never acted on.
	Curve() string
	// Sign returns a detached signature over payload.
	Sign(payload []byte) ([]byte, error)
}

// Policy is the chain-specific half: it reads a transaction and decides whether this key may
// sign it. It is the only component positioned to ask the question honestly, because it sits
// beside the key.
//
// It must be conservative. Anything it does not positively recognise is a refusal, because the
// payloads it cannot classify are exactly the ones worth worrying about. A policy that tried
// to anticipate every future use would end up permitting the one that drains you.
type Policy interface {
	// Approve returns nil if the payload may be signed, and an error NAMING the rule that
	// refused it otherwise. The name reaches the operator, so "mint authority is not revoked"
	// is the job and "invalid transaction" is not.
	Approve(payload []byte) error
}

// Tool names. Flynn calls exactly these two and nothing else. A signer advertising more than
// this is a signer doing more than signing.
const (
	PublicTool = "signer_public"
	SignTool   = "signer_sign"
)

// maxPayloadBytes bounds a signing request. A transaction is small; anything on this scale is
// not a transaction, and the parser should not be handed unbounded input from a process that
// is assumed to be compromisable.
const maxPayloadBytes = 64 << 10

// Serve runs a signer extension over stdio: it registers the two tools against key and policy,
// and blocks until the context ends or the stream closes.
func Serve(ctx context.Context, name, version string, key Key, policy Policy, r io.Reader, w io.Writer) error {
	if key == nil || policy == nil {
		return errors.New("signer: a signer needs both a key and a policy; one without the other is blind signing")
	}
	s := mcpserver.New(name, version)
	s.Register(publicTool(key))
	s.Register(signTool(key, policy))
	return s.Serve(ctx, r, w)
}

// publicTool answers with the public half, so the worker can build a transaction against a key
// it will never hold. Handing out a public key gives away nothing.
func publicTool(key Key) mcpserver.Tool {
	return mcpserver.Tool{
		Name:        PublicTool,
		Description: "Return the signer's public key. The private half never leaves this process.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(context.Context, json.RawMessage) (string, error) {
			out, err := json.Marshal(map[string]string{
				"publicKey": base64.StdEncoding.EncodeToString(key.Public()),
				"curve":     key.Curve(),
			})
			if err != nil {
				return "", fmt.Errorf("signer: encode public key: %w", err)
			}
			return string(out), nil
		},
	}
}

// signTool is the one that matters: parse, decide, and only then sign.
//
// A refusal is returned as an ERROR, never as a reply carrying an empty signature. The
// distinction is load-bearing: a caller that reads a reply and finds no signature could mistake
// it for a successful signature over nothing, and the one thing a signer may never do is let
// "I refused" be read as "here you go".
func signTool(key Key, policy Policy) mcpserver.Tool {
	return mcpserver.Tool{
		Name: SignTool,
		Description: "Sign a transaction, if the signing policy approves it. The transaction is parsed here, " +
			"and one that does not satisfy the policy is refused rather than signed.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"payload":{"type":"string","description":"base64 of the exact bytes to sign"}},"required":["payload"]}`),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(input, &args); err != nil {
				return "", fmt.Errorf("signer: malformed signing request: %w", err)
			}
			payload, err := base64.StdEncoding.DecodeString(args.Payload)
			if err != nil {
				return "", errors.New("signer: payload is not base64")
			}
			if len(payload) == 0 {
				return "", errors.New("signer: refusing to sign an empty payload")
			}
			if len(payload) > maxPayloadBytes {
				return "", fmt.Errorf("signer: refusing to sign %d bytes: a transaction is not this large", len(payload))
			}

			// Look before signing. This is the entire reason the key is in this process and
			// not in flynn: the question "may this be signed" can only be asked honestly by
			// something that both holds the key and understands the bytes.
			if refusal := policy.Approve(payload); refusal != nil {
				return "", fmt.Errorf("signer: refusing to sign: %w", refusal)
			}

			sig, err := key.Sign(payload)
			if err != nil {
				return "", fmt.Errorf("signer: %w", err)
			}
			out, err := json.Marshal(map[string]string{
				"signature": base64.StdEncoding.EncodeToString(sig),
			})
			if err != nil {
				return "", fmt.Errorf("signer: encode signature: %w", err)
			}
			return string(out), nil
		},
	}
}
