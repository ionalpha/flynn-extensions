// solana-signer holds the Solana signing key and the Solana transaction parser, and nothing
// else. Flynn routes a transaction here; this process parses it, decides, and either signs it
// or refuses. Flynn never sees the key and never reads the bytes.
//
// It has no network. A signer signs; it does not submit. The token extension owns the RPC
// connection and sends the signed transaction itself, so this process can run with its egress
// denied entirely, and a compromise of it reaches nothing.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"

	"github.com/ionalpha/flynn-extensions/signer"
	"github.com/ionalpha/flynn-extensions/solana"
)

// version is stamped by the release build (-X main.version). It must be a var: the linker
// ignores -X for a const, and the binary would report nothing.
var version = "dev"

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

// serve is the normal path: wait to be unlocked, then parse and sign.
//
// The key is NOT read here, and the passphrase does NOT come from the environment. The host
// launches an extension with its environment scrubbed, so no secret reaches this process by
// ambient means; the passphrase arrives over the MCP channel when the host unlocks us. Until
// then this process holds nothing and can sign nothing.
func serve(args []string) error {
	return serveWith(args, os.Stdin, os.Stdout)
}

// serveWith is serve over explicit streams, so the handshake can be driven in a test without a
// real subprocess on the other end of a pipe.
func serveWith(args []string, r io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("solana-signer", flag.ContinueOnError)
	keyPath := fs.String("key", "",
		"path to the sealed signing key (created by `solana-signer seal`). A released signer is "+
			"launched from a catalog spec whose arguments were fixed before this machine existed, so "+
			"it is normally told the path at unlock instead.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The path may come from the flag (an author running the binary by hand) or from the host at
	// unlock (a released signer, launched from a spec that could not have known where the key
	// would live). Neither is a secret. If both are given the flag wins, because the operator who
	// typed it is looking right at it.
	open := func(passphrase []byte, fromHost string) (signer.Key, error) {
		path := *keyPath
		if path == "" {
			path = fromHost
		}
		if path == "" {
			return nil, errors.New("no sealed key: pass --key, or have the host name one at unlock")
		}
		return signer.OpenEd25519Key(path, passphrase)
	}

	// The policy is bound to the key when the key is unlocked (see signer.BindsToKey): the
	// transaction's fee payer must be this very key, so a message asking it to underwrite
	// somebody else's transaction is refused. A pointer, because binding writes to it.
	policy := &solana.Solana{}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return signer.Serve(ctx, "solana-signer", version, open, policy, r, w)
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

	pass, err := readPassphrase()
	if err != nil {
		return err
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

// readPassphrase reads the passphrase without echoing it, when there is a terminal to read
// from. When there is not, it reads a line from standard input instead, so sealing a key can be
// scripted (a CI job, a provisioning step) rather than only ever done by hand.
//
// It is never a flag. A passphrase on the command line is recorded in the shell history and is
// visible in the process list to every other user on the machine, which is a worse place for it
// than the file it is protecting.
func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "passphrase: ")
		pass, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
		return pass, nil
	}

	// Not a terminal: take one line from stdin. The trailing newline a pipe or a heredoc adds
	// is not part of the passphrase, and a key sealed under "x\n" would refuse to open under
	// the "x" its owner typed.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
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
