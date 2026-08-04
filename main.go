package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openbao/openbao/sdk/v2/helper/shamir"
)

// Secrets are wrapped in an envelope before being split and unwrapped after
// combining, so combine can reject wrong or insufficient shares instead of
// reconstructing bytes that merely look like a valid secret.
//
//	envelope = magic(4) || version(1) || secret(N) || sha256(magic||version||secret)(32)
const (
	envelopeMagic      = "SHM1"
	envelopeVersion    = 1
	envelopeHeaderSize = len(envelopeMagic) + 1
)

func wrapSecret(secret []byte) []byte {
	envelope := make([]byte, 0, envelopeHeaderSize+len(secret)+sha256.Size)
	envelope = append(envelope, envelopeMagic...)
	envelope = append(envelope, envelopeVersion)
	envelope = append(envelope, secret...)
	sum := sha256.Sum256(envelope)
	return append(envelope, sum[:]...)
}

func unwrapSecret(envelope []byte) ([]byte, error) {
	if len(envelope) < envelopeHeaderSize+sha256.Size {
		return nil, errors.New("integrity check failed: reconstructed data is too short to be a valid envelope")
	}

	payload := envelope[:len(envelope)-sha256.Size]
	wantSum := envelope[len(envelope)-sha256.Size:]

	if string(payload[:len(envelopeMagic)]) != envelopeMagic || payload[len(envelopeMagic)] != envelopeVersion {
		return nil, errors.New("integrity check failed: reconstructed data is not a valid shamir-cli envelope")
	}

	gotSum := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(gotSum[:], wantSum) != 1 {
		return nil, errors.New("integrity check failed: shares do not reconstruct the original secret")
	}

	return payload[envelopeHeaderSize:], nil
}

// resolveAlias picks the value between a flag and its alias, using fs.Visit
// to tell "explicitly set" apart from "left at the zero value". Silently
// letting the last-parsed flag win would let a mistyped alias (e.g. -f
// pointing at the wrong file while -file points at the right one) change
// what gets split or combined without any warning.
func resolveAlias[T comparable](fs *flag.FlagSet, primary string, primaryVal T, alias string, aliasVal T) (T, error) {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	switch {
	case set[primary] && set[alias]:
		if primaryVal != aliasVal {
			var zero T
			return zero, fmt.Errorf("-%s and -%s were both set to different values (%v vs %v)", primary, alias, primaryVal, aliasVal)
		}
		return primaryVal, nil
	case set[primary]:
		return primaryVal, nil
	case set[alias]:
		return aliasVal, nil
	default:
		var zero T
		return zero, nil
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "split":
		if err := runSplit(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "combine":
		if err := runCombine(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Shamir's Secret Sharing CLI\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  shamir <command> [arguments]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  split      Split a secret from stdin or a file into N shares.\n")
	fmt.Fprintf(os.Stderr, "  combine    Reconstruct a secret from shares passed as arguments or stdin.\n\n")
	fmt.Fprintf(os.Stderr, "Use \"shamir split -h\" or \"shamir combine -h\" for more details.\n")
}

func runSplit(args []string) error {
	fs := flag.NewFlagSet("split", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var sharesFlag, sharesAlias int
	var thresholdFlag, thresholdAlias int
	var fileFlag, fileAlias string

	fs.IntVar(&sharesFlag, "shares", 0, "Total number of shares to create (2-255)")
	fs.IntVar(&sharesAlias, "n", 0, "Total number of shares to create (2-255) (alias for -shares)")
	fs.IntVar(&thresholdFlag, "threshold", 0, "Minimum shares required to reconstruct (2-255)")
	fs.IntVar(&thresholdAlias, "k", 0, "Minimum shares required to reconstruct (2-255) (alias for -threshold)")
	fs.StringVar(&fileFlag, "file", "", "Path to file containing the secret (reads from stdin if empty)")
	fs.StringVar(&fileAlias, "f", "", "Path to file containing the secret (alias for -file)")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: shamir split [flags]\n\n"+
			"Splits a secret, read from stdin or -file, into shares printed to stdout.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if len(fs.Args()) != 0 {
		return fmt.Errorf("split does not take positional arguments; use -file (got %q)", fs.Args())
	}

	sharesOpt, err := resolveAlias(fs, "shares", sharesFlag, "n", sharesAlias)
	if err != nil {
		return err
	}
	thresholdOpt, err := resolveAlias(fs, "threshold", thresholdFlag, "k", thresholdAlias)
	if err != nil {
		return err
	}
	fileOpt, err := resolveAlias(fs, "file", fileFlag, "f", fileAlias)
	if err != nil {
		return err
	}

	if sharesOpt == 0 {
		return errors.New("-shares or -n is required and must be between 2 and 255")
	}
	if thresholdOpt == 0 {
		return errors.New("-threshold or -k is required and must be between 2 and 255")
	}

	if sharesOpt < 2 || sharesOpt > 255 {
		return errors.New("shares must be between 2 and 255")
	}
	if thresholdOpt < 2 || thresholdOpt > 255 {
		return errors.New("threshold must be between 2 and 255")
	}
	if thresholdOpt > sharesOpt {
		return errors.New("threshold cannot be greater than shares")
	}

	var secret []byte
	if fileOpt != "" {
		secret, err = os.ReadFile(fileOpt)
		if err != nil {
			return fmt.Errorf("failed to read secret file: %w", err)
		}
	} else {
		secret, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read secret from stdin: %w", err)
		}
	}

	if len(secret) == 0 {
		return errors.New("secret cannot be empty")
	}

	envelope := wrapSecret(secret)
	var shares [][]byte

	// Registered before Split runs, so secret/envelope/shares are zeroed on
	// every return path, not only the successful one.
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
		for i := range envelope {
			envelope[i] = 0
		}
		for _, share := range shares {
			for i := range share {
				share[i] = 0
			}
		}
	}()

	shares, err = shamir.Split(envelope, sharesOpt, thresholdOpt)
	if err != nil {
		return fmt.Errorf("failed to split secret: %w", err)
	}

	for _, share := range shares {
		if _, err := fmt.Println(hex.EncodeToString(share)); err != nil {
			return fmt.Errorf("failed to write shares to stdout: %w", err)
		}
	}

	return nil
}

func runCombine(args []string) error {
	fs := flag.NewFlagSet("combine", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: shamir combine [share-file ...]\n\n"+
			"Reconstructs a secret from shares. Each share file holds one hex-encoded\n"+
			"share per line. With no arguments, shares are read from stdin instead.\n")
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	var rawShares []string
	remainingArgs := fs.Args()

	if len(remainingArgs) > 0 {
		for _, file := range remainingArgs {
			content, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read share file %s: %w", file, err)
			}
			tokens := strings.Fields(string(content))
			rawShares = append(rawShares, tokens...)
		}
	} else {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read shares from stdin: %w", err)
		}
		tokens := strings.Fields(string(content))
		rawShares = append(rawShares, tokens...)
	}

	if len(rawShares) == 0 {
		return errors.New("no shares provided")
	}

	var shares [][]byte
	var combined []byte
	var secret []byte

	// Registered before any share is decoded, so partially-decoded shares
	// are zeroed even if a later share fails to parse or Combine rejects
	// the set, not only on the successful path.
	defer func() {
		for _, share := range shares {
			for i := range share {
				share[i] = 0
			}
		}
		for i := range combined {
			combined[i] = 0
		}
		for i := range secret {
			secret[i] = 0
		}
	}()

	for i, raw := range rawShares {
		share, err := hex.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("invalid hex in share %d", i+1)
		}
		shares = append(shares, share)
	}

	var err error
	combined, err = shamir.Combine(shares)
	if err != nil {
		return fmt.Errorf("failed to reconstruct secret: %w", err)
	}

	var unwrapErr error
	secret, unwrapErr = unwrapSecret(combined)
	if unwrapErr != nil {
		return unwrapErr
	}

	if _, err := os.Stdout.Write(secret); err != nil {
		return fmt.Errorf("failed to write reconstructed secret to stdout: %w", err)
	}

	return nil
}
