package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/shamir"
)

func TestShamirSplitAndCombine(t *testing.T) {
	secret := []byte("SuperSecretSensitiveKey123")
	sharesCount := 5
	threshold := 3

	shares, err := shamir.Split(secret, sharesCount, threshold)
	if err != nil {
		t.Fatalf("Failed to split secret: %v", err)
	}

	if len(shares) != sharesCount {
		t.Errorf("Expected %d shares, got %d", sharesCount, len(shares))
	}

	subset := [][]byte{shares[0], shares[2], shares[4]}
	combined, err := shamir.Combine(subset)
	if err != nil {
		t.Fatalf("Failed to combine threshold shares: %v", err)
	}

	if string(combined) != string(secret) {
		t.Errorf("Expected reconstructed secret to be %s, got %s", string(secret), string(combined))
	}

	// Combine has no way to know the original threshold; with fewer shares
	// than required it silently returns bytes that are not the secret. The
	// CLI catches this through the integrity envelope, see TestIntegrityCheck.
	subsetTooSmall := [][]byte{shares[0], shares[1]}
	combinedGarbage, err := shamir.Combine(subsetTooSmall)
	if err == nil && string(combinedGarbage) == string(secret) {
		t.Errorf("Should not have successfully reconstructed the secret with fewer than threshold shares")
	}
}

func TestValidationRules(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantError string
	}{
		{
			name:      "missing shares",
			args:      []string{"split", "-threshold", "3"},
			wantError: "-shares or -n is required",
		},
		{
			name:      "missing threshold",
			args:      []string{"split", "-shares", "5"},
			wantError: "-threshold or -k is required",
		},
		{
			name:      "threshold > shares",
			args:      []string{"split", "-shares", "3", "-threshold", "5"},
			wantError: "threshold cannot be greater than shares",
		},
		{
			name:      "zero shares",
			args:      []string{"split", "-shares", "0", "-threshold", "3"},
			wantError: "-shares or -n is required",
		},
		{
			name:      "out of bounds shares",
			args:      []string{"split", "-shares", "256", "-threshold", "3"},
			wantError: "shares must be between 2 and 255",
		},
		{
			name:      "shares below minimum",
			args:      []string{"split", "-shares", "1", "-threshold", "1"},
			wantError: "shares must be between 2 and 255",
		},
		{
			name:      "threshold below minimum",
			args:      []string{"split", "-shares", "5", "-threshold", "1"},
			wantError: "threshold must be between 2 and 255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runSplit(tt.args[1:])
			if err == nil {
				t.Fatalf("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
			}
		})
	}
}

func TestHelpFlag(t *testing.T) {
	oldStderr := os.Stderr
	defer func() { os.Stderr = oldStderr }()

	captureStderr := func(fn func() error) (string, error) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		os.Stderr = w
		fnErr := fn()
		w.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatalf("Failed to read stderr: %v", err)
		}
		return buf.String(), fnErr
	}

	out, err := captureStderr(func() error { return runSplit([]string{"-h"}) })
	if err != nil {
		t.Errorf("runSplit -h should not return an error, got: %v", err)
	}
	if !strings.Contains(out, "Usage: shamir split") {
		t.Errorf("Expected split -h output to contain 'Usage: shamir split', got: %q", out)
	}

	out, err = captureStderr(func() error { return runCombine([]string{"-h"}) })
	if err != nil {
		t.Errorf("runCombine -h should not return an error, got: %v", err)
	}
	if !strings.Contains(out, "Usage: shamir combine") {
		t.Errorf("Expected combine -h output to contain 'Usage: shamir combine', got: %q", out)
	}
}

func TestSplitRejectsPositionalArgs(t *testing.T) {
	err := runSplit([]string{"-shares", "3", "-threshold", "2", "secret.txt"})
	if err == nil {
		t.Fatalf("Expected an error for a positional argument, got nil")
	}
	if !strings.Contains(err.Error(), "does not take positional arguments") {
		t.Errorf("Expected error about positional arguments, got: %v", err)
	}
}

func TestSplitStdoutWriteError(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("Failed to write temporary secret file: %v", err)
	}

	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error: %v", err)
	}
	r.Close() // close the read end so writes to w fail with a broken pipe
	os.Stdout = w

	err = runSplit([]string{"-shares", "3", "-threshold", "2", "-file", secretFile})
	w.Close()
	if err == nil {
		t.Fatalf("Expected an error when the stdout write fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to write shares to stdout") {
		t.Errorf("Expected error containing 'failed to write shares to stdout', got: %v", err)
	}
}

func TestAliasConflict(t *testing.T) {
	t.Run("conflicting -shares/-n rejected", func(t *testing.T) {
		err := runSplit([]string{"-shares", "5", "-n", "3", "-threshold", "2"})
		if err == nil {
			t.Fatalf("Expected an error for conflicting -shares/-n, got nil")
		}
		if !strings.Contains(err.Error(), "-shares and -n") {
			t.Errorf("Expected error about conflicting -shares/-n, got: %v", err)
		}
	})

	t.Run("conflicting -file/-f rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := filepath.Join(tmpDir, "a.txt")
		b := filepath.Join(tmpDir, "b.txt")
		if err := os.WriteFile(a, []byte("secret-a"), 0600); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}
		if err := os.WriteFile(b, []byte("secret-b"), 0600); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		err := runSplit([]string{"-shares", "3", "-threshold", "2", "-file", a, "-f", b})
		if err == nil {
			t.Fatalf("Expected an error for conflicting -file/-f, got nil")
		}
		if !strings.Contains(err.Error(), "-file and -f") {
			t.Errorf("Expected error about conflicting -file/-f, got: %v", err)
		}
	})

	t.Run("conflicting -threshold/-k rejected", func(t *testing.T) {
		err := runSplit([]string{"-shares", "5", "-threshold", "3", "-k", "2"})
		if err == nil {
			t.Fatalf("Expected an error for conflicting -threshold/-k, got nil")
		}
		if !strings.Contains(err.Error(), "-threshold and -k") {
			t.Errorf("Expected error about conflicting -threshold/-k, got: %v", err)
		}
	})

	t.Run("same value on both aliases is not a conflict", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		w.Close() // empty stdin
		os.Stdin = r

		err = runSplit([]string{"-shares", "3", "-n", "3", "-threshold", "2"})
		// Empty stdin means a "secret cannot be empty" error is expected;
		// what matters here is that it's not an alias-conflict error.
		if err == nil {
			t.Fatalf("Expected an error (empty secret), got nil")
		}
		if strings.Contains(err.Error(), "were both set to different values") {
			t.Errorf("Same-value aliases should not be treated as a conflict, got: %v", err)
		}
	})
}

func TestBinarySecretWithNUL(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.bin")
	secretData := []byte{'a', 0x00, 'b', 0x00, 'c'}
	if err := os.WriteFile(secretFile, secretData, 0600); err != nil {
		t.Fatalf("Failed to write temporary secret file: %v", err)
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error: %v", err)
	}
	os.Stdout = w
	err = runSplit([]string{"-shares", "3", "-threshold", "2", "-file", secretFile})
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("runSplit failed: %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}
	lines := strings.Fields(buf.String())
	if len(lines) != 3 {
		t.Fatalf("Expected 3 shares, got %d", len(lines))
	}

	shareFiles := make([]string, 2)
	for i, line := range lines[:2] {
		sf := filepath.Join(tmpDir, fmt.Sprintf("bin_share_%d", i))
		if err := os.WriteFile(sf, []byte(line), 0600); err != nil {
			t.Fatalf("Failed to write share file: %v", err)
		}
		shareFiles[i] = sf
	}

	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error: %v", err)
	}
	os.Stdout = w2
	err = runCombine(shareFiles)
	w2.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("runCombine failed: %v", err)
	}

	var combinedBuf bytes.Buffer
	if _, err := combinedBuf.ReadFrom(r2); err != nil {
		t.Fatalf("Failed to read combine output: %v", err)
	}
	if !bytes.Equal(combinedBuf.Bytes(), secretData) {
		t.Errorf("Expected reconstructed secret %v, got %v", secretData, combinedBuf.Bytes())
	}
}

func TestCombineMixedSecretsSameLength(t *testing.T) {
	tmpDir := t.TempDir()
	fileA := filepath.Join(tmpDir, "a.txt")
	fileB := filepath.Join(tmpDir, "b.txt")
	secretA := "SecretoUno12345"
	secretB := "SecretoDos67890"
	if len(secretA) != len(secretB) {
		t.Fatalf("test setup error: secrets must be the same length")
	}
	if err := os.WriteFile(fileA, []byte(secretA), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := os.WriteFile(fileB, []byte(secretB), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	splitToLines := func(file string) []string {
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		os.Stdout = w
		err = runSplit([]string{"-shares", "3", "-threshold", "2", "-file", file})
		w.Close()
		os.Stdout = oldStdout
		if err != nil {
			t.Fatalf("runSplit failed: %v", err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatalf("Failed to read from pipe: %v", err)
		}
		return strings.Fields(buf.String())
	}

	linesA := splitToLines(fileA)
	linesB := splitToLines(fileB)

	shareA := filepath.Join(tmpDir, "share_a")
	shareB := filepath.Join(tmpDir, "share_b")
	if err := os.WriteFile(shareA, []byte(linesA[0]), 0600); err != nil {
		t.Fatalf("Failed to write share file: %v", err)
	}
	if err := os.WriteFile(shareB, []byte(linesB[0]), 0600); err != nil {
		t.Fatalf("Failed to write share file: %v", err)
	}

	err := runCombine([]string{shareA, shareB})
	if err == nil {
		t.Fatalf("Expected an integrity check error, got nil")
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Errorf("Expected error containing 'integrity check failed', got: %v", err)
	}
}

func TestCombineTamperedShare(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("TamperTestSecret"), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error: %v", err)
	}
	os.Stdout = w
	err = runSplit([]string{"-shares", "3", "-threshold", "2", "-file", secretFile})
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("runSplit failed: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}
	lines := strings.Fields(buf.String())
	if len(lines) != 3 {
		t.Fatalf("Expected 3 shares, got %d", len(lines))
	}

	// Flip one hex digit in the first share, keeping it valid hex.
	tampered := []rune(lines[0])
	if tampered[0] == '0' {
		tampered[0] = '1'
	} else {
		tampered[0] = '0'
	}
	lines[0] = string(tampered)

	shareFiles := make([]string, 2)
	for i, line := range lines[:2] {
		sf := filepath.Join(tmpDir, fmt.Sprintf("tamper_share_%d", i))
		if err := os.WriteFile(sf, []byte(line), 0600); err != nil {
			t.Fatalf("Failed to write share file: %v", err)
		}
		shareFiles[i] = sf
	}

	err = runCombine(shareFiles)
	if err == nil {
		t.Fatalf("Expected an error for a tampered share, got nil")
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Errorf("Expected error containing 'integrity check failed', got: %v", err)
	}
}

func TestFileHandling(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	secretData := []byte("TopSecretData")
	if err := os.WriteFile(secretFile, secretData, 0600); err != nil {
		t.Fatalf("Failed to write temporary secret file: %v", err)
	}

	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error: %v", err)
	}
	os.Stdout = w

	err = runSplit([]string{"-shares", "3", "-threshold", "2", "-file", secretFile})
	w.Close()
	if err != nil {
		t.Fatalf("runSplit failed: %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}

	lines := strings.Fields(buf.String())
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines of shares, got %d. Output: %q", len(lines), buf.String())
	}

	shareFiles := make([]string, 3)
	for i, line := range lines {
		sf := filepath.Join(tmpDir, t.Name()+fmt.Sprintf("_share_%d", i))
		if err := os.WriteFile(sf, []byte(line), 0600); err != nil {
			t.Fatalf("Failed to write share file: %v", err)
		}
		shareFiles[i] = sf
	}

	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error 2: %v", err)
	}
	os.Stdout = w2

	err = runCombine(shareFiles[:2])
	w2.Close()
	if err != nil {
		t.Fatalf("runCombine failed: %v", err)
	}

	var combinedBuf bytes.Buffer
	_, err = combinedBuf.ReadFrom(r2)
	if err != nil {
		t.Fatalf("Failed to read from combine pipe: %v", err)
	}

	if combinedBuf.String() != string(secretData) {
		t.Errorf("Expected combined secret to be %q, got %q", string(secretData), combinedBuf.String())
	}
}

func TestCombineValidation(t *testing.T) {
	t.Run("no shares provided", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		w.Close() // close immediately so ReadAll returns EOF
		os.Stdin = r

		err = runCombine([]string{})
		if err == nil {
			t.Fatalf("Expected error for no shares, got nil")
		}
		if !strings.Contains(err.Error(), "no shares provided") {
			t.Errorf("Expected error containing 'no shares provided', got: %v", err)
		}
	})

	t.Run("invalid hex share", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		_, _ = w.Write([]byte("not-a-hex-string\n"))
		w.Close()
		os.Stdin = r

		err = runCombine([]string{})
		if err == nil {
			t.Fatalf("Expected error for invalid hex, got nil")
		}
		if !strings.Contains(err.Error(), "invalid hex in share") {
			t.Errorf("Expected error containing 'invalid hex in share', got: %v", err)
		}
	})

	t.Run("invalid file path", func(t *testing.T) {
		err := runCombine([]string{"nonexistent_file_xyz_123"})
		if err == nil {
			t.Fatalf("Expected error for nonexistent file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to read share file") {
			t.Errorf("Expected error containing 'failed to read share file', got: %v", err)
		}
	})
}

func TestIntegrityCheck(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	secret := "TopSecretPassphrase!"
	if err := os.WriteFile(secretFile, []byte(secret), 0600); err != nil {
		t.Fatalf("Failed to write temporary secret file: %v", err)
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe error: %v", err)
	}
	os.Stdout = w
	err = runSplit([]string{"-shares", "5", "-threshold", "3", "-file", secretFile})
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("runSplit failed: %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}
	lines := strings.Fields(buf.String())
	if len(lines) != 5 {
		t.Fatalf("Expected 5 shares, got %d", len(lines))
	}

	t.Run("insufficient shares fail the integrity check", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r2, w2, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		fmt.Fprintln(w2, lines[0])
		fmt.Fprintln(w2, lines[1])
		w2.Close()
		os.Stdin = r2

		err = runCombine([]string{})
		if err == nil {
			t.Fatalf("Expected an integrity check error, got nil")
		}
		if !strings.Contains(err.Error(), "integrity check failed") {
			t.Errorf("Expected error containing 'integrity check failed', got: %v", err)
		}
	})

	t.Run("threshold shares reconstruct the original secret", func(t *testing.T) {
		oldStdin, oldStdout := os.Stdin, os.Stdout
		defer func() { os.Stdin, os.Stdout = oldStdin, oldStdout }()

		rIn, wIn, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		fmt.Fprintln(wIn, lines[0])
		fmt.Fprintln(wIn, lines[1])
		fmt.Fprintln(wIn, lines[2])
		wIn.Close()
		os.Stdin = rIn

		rOut, wOut, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe error: %v", err)
		}
		os.Stdout = wOut

		err = runCombine([]string{})
		wOut.Close()
		if err != nil {
			t.Fatalf("runCombine failed: %v", err)
		}

		var out bytes.Buffer
		if _, err := out.ReadFrom(rOut); err != nil {
			t.Fatalf("Failed to read combine output: %v", err)
		}
		if out.String() != secret {
			t.Errorf("Expected reconstructed secret %q, got %q", secret, out.String())
		}
	})
}
