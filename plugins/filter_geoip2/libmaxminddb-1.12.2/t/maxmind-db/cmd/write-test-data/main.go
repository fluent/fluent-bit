// write-test-data generates test mmdb files.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/maxmind/MaxMind-DB/pkg/writer"
)

func main() {
	source := flag.String("source", "", "Source data directory")
	target := flag.String("target", "", "Destination directory for the generated mmdb files")

	flag.Parse()

	w, err := writer.New(*source, *target)
	if err != nil {
		fmt.Printf("creating writer: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteIPv4TestDB(); err != nil {
		fmt.Printf("writing IPv4 test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteIPv6TestDB(); err != nil {
		fmt.Printf("writing IPv6 test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteMixedIPTestDB(); err != nil {
		fmt.Printf("writing IPv6 test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteNoIPv4TestDB(); err != nil {
		fmt.Printf("writing no IPv4 test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteNoMapTestDB(); err != nil {
		fmt.Printf("writing no map test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteMetadataPointersTestDB(); err != nil {
		fmt.Printf("writing metadata pointers test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteDecoderTestDB(); err != nil {
		fmt.Printf("writing decoder test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteDeeplyNestedStructuresTestDB(); err != nil {
		fmt.Printf("writing decoder test databases: %+v\n", err)
		os.Exit(1)
	}

	if err := w.WriteGeoIP2TestDB(); err != nil {
		fmt.Printf("writing GeoIP2 test databases: %+v\n", err)
		os.Exit(1)
	}
}
