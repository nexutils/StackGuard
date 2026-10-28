//go:build js && wasm

// Package main is the WASM entry point for the StackGuard playground.
// Build: GOOS=js GOARCH=wasm go build -o web/stackguard.wasm ./cmd/playground
package main

import (
	"context"
	"encoding/json"
	"syscall/js"

	"github.com/nexutils/StackGuard/internal/engine"
	"github.com/nexutils/StackGuard/internal/loader"
	"github.com/nexutils/StackGuard/internal/models"
	"github.com/nexutils/StackGuard/internal/parser"
	"github.com/nexutils/StackGuard/internal/parser/all"
	"github.com/nexutils/StackGuard/rules"
)

func main() {
	js.Global().Set("stackguardScan", js.FuncOf(scan))
	js.Global().Set("stackguardTargets", js.FuncOf(targets))

	// Block forever so the Go runtime stays alive.
	select {}
}

// scan is called from JS: stackguardScan(filesJSON) → Promise<string>
// filesJSON is a JSON array of {path, content} objects.
func scan(_ js.Value, args []js.Value) any {
	handler := js.FuncOf(func(_ js.Value, pArgs []js.Value) any {
		resolve := pArgs[0]
		reject := pArgs[1]

		go func() {
			result, err := doScan(args)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(result)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func doScan(args []js.Value) (string, error) {
	if len(args) < 1 {
		return "", nil
	}
	filesJSON := args[0].String()

	var files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(filesJSON), &files); err != nil {
		return "", err
	}

	set, err := loader.Load(
		loader.Options{KnownTargets: all.Registry().Names()},
		loader.Layer{Name: "embedded", FS: rules.FS, Embedded: true},
	)
	if err != nil {
		return "", err
	}

	e, err := engine.New(set.All(), engine.Options{})
	if err != nil {
		return "", err
	}

	sources := make([]parser.Source, len(files))
	for i, f := range files {
		sources[i] = parser.Source{Path: f.Path, Content: []byte(f.Content)}
	}

	rep, err := e.ScanSources(context.Background(), sources)
	if err != nil {
		return "", err
	}

	out, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// targets returns the list of supported scan targets as JSON.
func targets(_ js.Value, _ []js.Value) any {
	names := all.Registry().Names()
	b, _ := json.Marshal(names)
	return string(b)
}

// wasmResult is kept minimal to avoid bloating the WASM binary.
type wasmResult struct {
	Score    models.Score     `json:"score"`
	Findings []models.Finding `json:"findings"`
	Stats    models.ScanStats `json:"stats"`
}
