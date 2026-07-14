// solana-signer holds the Solana signing key and the Solana transaction parser, and nothing
// else. Flynn routes a transaction here; this process parses it, decides, and either signs it
// or refuses. Flynn never sees the key and never reads the bytes.
//
// It has no network. A signer signs; it does not submit. The token extension owns the RPC
// connection and sends the signed transaction itself, so this process can run with its egress
// denied entirely, and a compromise of it reaches nothing.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/ionalpha/flynn-extensions/signer"
	"github.com/ionalpha/flynn-extensions/solana"
	"golang.org/x/term"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "solana-signer: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	// `seal` is an operator command, run once, at a terminal. Everything else is the signer
	// serving MCP over stdio, which is how flynn launches it.
	if len(args) > 0 && args[0] == "seal" {
		return seal(args[1:])
	}
	return serve(args)
}

// serve is the normal path: unseal the key, build the policy around it, speak MCP on stdio.
func serve(args []string) error {
	fs := flag.NewFlagSet("solana-signer", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the sealed signing key (created by `solana-signer seal`)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("no --key: a signer with no key can sign nothing")
	}

	// The passphrase arrives by environment, because flynn launches this process without a
	// terminal to prompt at. The key on disk stays encrypted either way: an attacker who reads
	// the disk gets a file they still have to break.
	pass := []byte(os.Getenv("FLYNN_SIGNER_PASSPHRASE"))
	if len(pass) == 0 {
		return errors.New("FLYNN_SIGNER_PASSPHRASE is not set, so the sealed key cannot be opened")
	}

	key, err := signer.OpenEd25519Key(*keyPath, pass)
	if err != nil {
		return err
	}

	// The policy is built AROUND this key: the transaction's fee payer must be this very key,
	// so a message asking it to underwrite somebody else's transaction is refused. Binding the
	// policy to the key is what stops a stolen-but-valid-looking transaction from being signed.
	policy := solana.Solana{Payer: key.Public()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return signer.Serve(ctx, "solana-signer", version, key, policy, os.Stdin, os.Stdout)
}

// seal imports a raw key and encrypts it, so the raw key can be destroyed. It reads the
// passphrase from the terminal rather than a flag: a passphrase on the command line lands in
// the shell history and the process list.
func seal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	in := fs.String("in", "", "path to a raw key file (a JSON array of the 64 private-key bytes)")
	out := fs.String("out", "", "path to write the sealed key to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		return errors.New("seal needs --in (the raw key) and --out (where to seal it)")
	}

	priv, err := readRawKey(*in)
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, "passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return errors.New("refusing to seal a key under an empty passphrase")
	}

	if err := signer.SealEd25519Key(*out, priv, pass); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sealed to %s\nDelete %s now: it is the key, in the clear.\n", *out, *in)
	return nil
}

// readRawKey reads the 64-byte JSON array form the Solana tooling emits.
func readRawKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the operator names their own key file
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	var nums []int
	if err := json.Unmarshal(raw, &nums); err != nil {
		return nil, errors.New("the key must be a JSON array of the 64 private-key bytes")
	}
	if len(nums) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the key must be %d bytes, got %d", ed25519.PrivateKeySize, len(nums))
	}
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for i, n := range nums {
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("key byte %d is out of range", i)
		}
		key[i] = byte(n)
	}
	return key, nil
}
