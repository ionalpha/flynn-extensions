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
	"sync"

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
	// UnlockTool opens the sealed key and answers with its public half. It is the mount
	// handshake, and it is the only way the key becomes usable.
	UnlockTool = "signer_unlock"
	// SignTool signs a payload, or refuses it. It refuses outright until the key is unlocked.
	SignTool = "signer_sign"
)

// Opener turns a passphrase into a usable Key. It is how custody is chosen: a sealed file
// unseals under the passphrase, and a hardware device ignores it and answers from the device.
//
// The passphrase arrives over the MCP channel rather than the environment, because the host
// launches this process with its environment scrubbed: no secret reaches an extension by
// ambient means, and a secret it is meant to have is one the operator handed it deliberately.
// The host holds the passphrase; this process holds the key. The host never sees the key.
//
// keyPath arrives the same way, and for a duller reason: a released extension is launched from
// a catalog spec whose arguments are fixed when the spec is written, so they cannot name a file
// on a machine nobody has seen yet. The path is not a secret and the host learns nothing from
// holding it: it is this process that opens the file, and the key inside it never travels back.
//
// That is the right split for the threat this design defends against, which is a compromised
// WORKER extension, not a compromised host. A host that has been compromised launches whatever
// binary it likes and is past arguing with; keeping the key out of it buys nothing there. What
// it buys is that the extension which BUILDS a transaction can never sign one.
type Opener func(passphrase []byte, keyPath string) (Key, error)

// maxPayloadBytes bounds a signing request. A transaction is small; anything on this scale is
// not a transaction, and the parser should not be handed unbounded input from a process that
// is assumed to be compromisable.
const maxPayloadBytes = 64 << 10

// vault holds the key once it is unlocked. It starts empty: a signer that has just started
// cannot sign anything, and stays that way until an operator-held passphrase arrives.
type vault struct {
	mu  sync.RWMutex
	key Key
}

func (v *vault) get() Key {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.key
}

func (v *vault) set(k Key) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.key = k
}

// Serve runs a signer extension over stdio: it registers the two tools against the opener and
// the policy, and blocks until the context ends or the stream closes.
//
// The key is NOT loaded here. The process starts locked and signs nothing until the host
// unlocks it, so a signer that is launched but never unlocked is inert.
func Serve(ctx context.Context, name, version string, open Opener, policy Policy, r io.Reader, w io.Writer) error {
	if open == nil || policy == nil {
		return errors.New("signer: a signer needs both a key and a policy; one without the other is blind signing")
	}
	v := &vault{}
	s := mcpserver.New(name, version)
	s.Register(unlockTool(v, open, policy))
	s.Register(signTool(v, policy))
	return s.Serve(ctx, r, w)
}

// unlockTool opens the key under the host's passphrase and answers with its public half, so the
// worker can build a transaction against a key it will never hold. Handing out a public key
// gives away nothing.
//
// A policy that must be bound to the key (the fee payer has to BE this key, or the signer would
// be underwriting somebody else's transaction) is bound here, once the key is known.
func unlockTool(v *vault, open Opener, policy Policy) mcpserver.Tool {
	return mcpserver.Tool{
		Name: UnlockTool,
		Description: "Unlock the signing key and return its public half. The private half never leaves " +
			"this process, and the signer can do nothing at all until this succeeds.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"passphrase":{"type":"string","description":"passphrase that opens the sealed key"},` +
			`"keyPath":{"type":"string","description":"path to the sealed key, when the signer was not launched with one"}}}`),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Passphrase string `json:"passphrase"`
				KeyPath    string `json:"keyPath"`
			}
			if err := json.Unmarshal(input, &args); err != nil {
				return "", fmt.Errorf("signer: malformed unlock request: %w", err)
			}
			key, err := open([]byte(args.Passphrase), args.KeyPath)
			if err != nil {
				return "", err
			}
			if b, ok := policy.(BindsToKey); ok {
				b.BindKey(key.Public())
			}
			v.set(key)

			out, merr := json.Marshal(map[string]string{
				"publicKey": base64.StdEncoding.EncodeToString(key.Public()),
				"curve":     key.Curve(),
			})
			if merr != nil {
				return "", fmt.Errorf("signer: encode public key: %w", merr)
			}
			return string(out), nil
		},
	}
}

// BindsToKey is the optional half of a Policy whose rules depend on the key itself: the Solana
// policy requires the transaction's fee payer to BE the signing key, which it cannot check
// until the key is unlocked. A policy that does not implement it is judged on the payload
// alone.
type BindsToKey interface {
	// BindKey tells the policy which key it is guarding.
	BindKey(pub []byte)
}

// signTool is the one that matters: parse, decide, and only then sign.
//
// A refusal is returned as an ERROR, never as a reply carrying an empty signature. The
// distinction is load-bearing: a caller that reads a reply and finds no signature could mistake
// it for a successful signature over nothing, and the one thing a signer may never do is let
// "I refused" be read as "here you go".
func signTool(v *vault, policy Policy) mcpserver.Tool {
	return mcpserver.Tool{
		Name: SignTool,
		Description: "Sign a transaction, if the signing policy approves it. The transaction is parsed here, " +
			"and one that does not satisfy the policy is refused rather than signed.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"payload":{"type":"string","description":"base64 of the exact bytes to sign"}},"required":["payload"]}`),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			key := v.get()
			if key == nil {
				return "", errors.New("signer: the key is locked, so there is nothing to sign with")
			}
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
