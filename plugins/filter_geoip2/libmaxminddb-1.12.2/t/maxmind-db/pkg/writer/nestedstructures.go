package writer

import (
	"fmt"
	"net/netip"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"go4.org/netipx"
)

// WriteDeeplyNestedStructuresTestDB writes an mmdb file with deeply nested record value types.
func (w *Writer) WriteDeeplyNestedStructuresTestDB() error {
	dbWriter, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: "MaxMind DB Nested Data Structures",
			Description: map[string]string{
				"en": "MaxMind DB Nested Data Structures Test database - contains deeply nested map/array structures",
			},
			DisableIPv4Aliasing:     false,
			IncludeReservedNetworks: true,
			IPVersion:               6,
			Languages:               []string{"en"},
			RecordSize:              24,
		},
	)
	if err != nil {
		return fmt.Errorf("creating mmdbwriter: %w", err)
	}

	addrs, err := parseIPSlice(ipSample)
	if err != nil {
		return fmt.Errorf("parsing ip addresses: %w", err)
	}
	if err := insertNestedStructure(dbWriter, addrs); err != nil {
		return fmt.Errorf("inserting all types records: %w", err)
	}

	if err := w.write(dbWriter, "MaxMind-DB-test-nested.mmdb"); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	return nil
}

// insertNestedStructure inserts records with deeply nested structures.
func insertNestedStructure(w *mmdbwriter.Tree, ipAddresses []netip.Prefix) error {
	nestedStruct := mmdbtype.Map{
		"map1": mmdbtype.Map{
			"map2": mmdbtype.Map{
				"array": mmdbtype.Slice{
					mmdbtype.Map{
						"map3": mmdbtype.Map{
							"a": mmdbtype.Uint32(1),
							"b": mmdbtype.Uint32(2),
							"c": mmdbtype.Uint32(3),
						},
					},
				},
			},
		},
	}

	for _, addr := range ipAddresses {
		err := w.Insert(
			netipx.PrefixIPNet(addr),
			nestedStruct,
		)
		if err != nil {
			return fmt.Errorf("inserting ip: %w", err)
		}
	}
	return nil
}
