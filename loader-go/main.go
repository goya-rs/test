package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Mirrors the goya-template generated {{project-name}}-go/main.go load path:
//   ebpf.LoadCollectionSpecFromReader + ebpf.NewCollection
// Usage: ./loader <path-to-elf>
func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
	path := ".ebpf/test"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer f.Close()

	specEbpf, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		log.Fatalf("LoadCollectionSpec failed: %v", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(specEbpf, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 1 << 20},
	})
	if err != nil {
		// %+Nv prints the full verifier log for a VerifierError
		fmt.Fprintf(os.Stderr, "LOAD ERROR: %s\n", err)
		os.Exit(1)
	}
	defer coll.Close()
	for name := range coll.Programs {
		fmt.Printf("OK: loaded program %q\n", name)
	}
	fmt.Println("OK: collection loaded")
}
