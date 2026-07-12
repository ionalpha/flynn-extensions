// Package rigor is a gate, not a library: its one test walks the module and fails if a
// package that should carry rigor does not. It exists so the property tests, fuzz targets, and
// fault-injection this repo relies on cannot be quietly dropped, and so a NEW package cannot
// ship without them by simply never being added to a list. The token engine handles real
// money; "we have tests" has to be enforced, not hoped.
package rigor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rapidImport, imported by a test file, satisfies the property-test requirement.
const rapidImport = "pgregory.net/rapid"

// propertyExempt lists packages that carry neither a property test nor a fuzz target and are
// allowed to. Keep it tiny and justified: a package earns a place here only by having no logic
// worth a property (a bare data type, a thin main). Never add a package that parses input.
var propertyExempt = map[string]bool{
	"cmd/example":    true, // the example extension: a documentation stub, no logic
	"clock":          true, // a time port; its behaviour is the standard library's
	"internal/rigor": true, // this gate itself
}

// fuzzRequired lists packages that parse input they do not control and so MUST carry a fuzz
// target. A parser without a fuzzer is a crash waiting for the input that finds it. Grow this
// as new parsers appear; a package here that loses its fuzz target fails the gate.
var fuzzRequired = map[string]bool{
	"token":     true, // ClassifyEndpoint, ContentAddressed, the metadata encoder
	"cmd/token": true, // parseSupply, on the tool boundary
}

func TestEveryPackageCarriesItsRigor(t *testing.T) {
	root := moduleRoot(t)
	pkgs := map[string]*pkgFacts{}

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") && name != "." {
				if p != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		rel = filepath.ToSlash(rel)
		f := pkgs[rel]
		if f == nil {
			f = &pkgFacts{}
			pkgs[rel] = f
		}
		return f.observe(p)
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for pkg, f := range pkgs {
		if pkg == "." || !f.hasProdGo {
			continue // not a real package, or tests only
		}
		if !propertyExempt[pkg] && !f.hasProperty && !f.hasFuzz {
			t.Errorf("package %q carries neither a property test (import %q) nor a fuzz target: money-handling code must have at least one", pkg, rapidImport)
		}
		if fuzzRequired[pkg] && !f.hasFuzz {
			t.Errorf("package %q parses untrusted input and must carry a fuzz target, but has none", pkg)
		}
		if propertyExempt[pkg] && (f.hasProperty || f.hasFuzz) {
			t.Errorf("package %q is on the property-exempt list but now has a property test or fuzzer; remove it from the exemption", pkg)
		}
	}
}

type pkgFacts struct {
	hasProdGo   bool // at least one non-test .go file
	hasProperty bool // a test imports rapid
	hasFuzz     bool // a test declares a Fuzz target
}

func (f *pkgFacts) observe(path string) error {
	isTest := strings.HasSuffix(path, "_test.go")
	if !isTest {
		f.hasProdGo = true
		return nil
	}
	src, err := os.ReadFile(path) //nolint:gosec // walking our own module tree
	if err != nil {
		return err
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		return err
	}
	for _, imp := range file.Imports {
		if strings.Trim(imp.Path.Value, `"`) == rapidImport {
			f.hasProperty = true
		}
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && strings.HasPrefix(fn.Name.Name, "Fuzz") && fn.Recv == nil {
			f.hasFuzz = true
		}
	}
	return nil
}

// moduleRoot finds the directory holding go.mod by walking up from this test file.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test directory")
		}
		dir = parent
	}
}
