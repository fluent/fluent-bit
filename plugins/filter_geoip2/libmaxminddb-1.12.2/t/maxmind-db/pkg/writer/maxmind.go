package writer

import (
	"fmt"
	"net/netip"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"go4.org/netipx"
)

// WriteIPv4TestDB writes mmdb files for an ip range between 1.1.1.1 and 1.1.1.32
// with various record sizes.
func (w *Writer) WriteIPv4TestDB() error {
	ipRange, err := parseIPRange("1.1.1.1", "1.1.1.32")
	if err != nil {
		return fmt.Errorf("parsing ip range: %w", err)
	}

	for _, recordSize := range []int{24, 28, 32} {
		err := w.writeMaxMindTestDB(
			recordSize,
			[]netipx.IPRange{ipRange},
			"ipv4",
		)
		if err != nil {
			return fmt.Errorf("writing test database: %w", err)
		}
	}

	return nil
}

// WriteIPv6TestDB writes mmdb files for an ip range between ::1:ffff:ffff and ::2:0000:0059
// with various record sizes.
func (w *Writer) WriteIPv6TestDB() error {
	ipRange, err := parseIPRange("::1:ffff:ffff", "::2:0000:0059")
	if err != nil {
		return fmt.Errorf("parsing ip range: %w", err)
	}

	for _, recordSize := range []int{24, 28, 32} {
		err := w.writeMaxMindTestDB(
			recordSize,
			[]netipx.IPRange{ipRange},
			"ipv6",
		)
		if err != nil {
			return fmt.Errorf("writing test database: %w", err)
		}
	}

	return nil
}

// WriteMixedIPTestDB writes mmdb files for a mixed ip version range between ::1:ffff:ffff and ::2:0000:0059
// with various record sizes.
func (w *Writer) WriteMixedIPTestDB() error {
	ipv6Range, err := parseIPRange("::1:ffff:ffff", "::2:0000:0059")
	if err != nil {
		return fmt.Errorf("parsing ip range: %w", err)
	}

	ipv4Range, err := parseIPRange("1.1.1.1", "1.1.1.32")
	if err != nil {
		return fmt.Errorf("parsing ip range: %w", err)
	}

	for _, recordSize := range []int{24, 28, 32} {
		err := w.writeMaxMindTestDB(
			recordSize,
			[]netipx.IPRange{ipv6Range, ipv4Range},
			"mixed",
		)
		if err != nil {
			return fmt.Errorf("writing test database: %w", err)
		}
	}

	return nil
}

// writeMaxMindTestDB writes test mmdb files.
func (w *Writer) writeMaxMindTestDB(
	recordSize int,
	ipRange []netipx.IPRange,
	ipVersionName string,
) error {
	ipVersion := 6
	if ipRange[0].From().Is4() {
		ipVersion = 4
	}

	metadata := map[string]string{}
	metadata["en"] = "Test Database"
	metadata["zh"] = "Test Database Chinese"

	dbWriter, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType:        "Test",
			Description:         metadata,
			DisableIPv4Aliasing: ipVersion == 4,
			IPVersion:           ipVersion,
			Languages:           []string{"en", "zh"},
			RecordSize:          recordSize,
		},
	)
	if err != nil {
		return fmt.Errorf("creating mmdbwriter: %w", err)
	}

	for _, ir := range ipRange {
		for _, prefix := range ir.Prefixes() {
			ipString := prefix.Addr().String()
			if ipVersion == 6 && prefix.Addr().Is4() {
				ipString = "::" + ipString
			}

			err := dbWriter.Insert(
				netipx.PrefixIPNet(prefix),
				mmdbtype.Map{
					"ip": mmdbtype.String(ipString),
				},
			)
			if err != nil {
				return fmt.Errorf("inserting ip: %w", err)
			}
		}
	}

	fileName := fmt.Sprintf("MaxMind-DB-test-%s-%d.mmdb", ipVersionName, recordSize)
	if err := w.write(dbWriter, fileName); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}

	return nil
}

// WriteNoIPv4TestDB writes an mmdb file with no ipv4 records.
func (w *Writer) WriteNoIPv4TestDB() error {
	dbWriter, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: "MaxMind DB No IPv4 Search Tree",
			Description: map[string]string{
				"en": "MaxMind DB No IPv4 Search Tree",
			},
			DisableIPv4Aliasing:     true,
			IncludeReservedNetworks: true,
			IPVersion:               6,
			Languages:               []string{"en"},
			RecordSize:              24,
		},
	)
	if err != nil {
		return fmt.Errorf("creating mmdbwriter: %w", err)
	}

	addr, err := netip.ParsePrefix("::/64")
	if err != nil {
		return fmt.Errorf("parsing ip: %w", err)
	}

	err = dbWriter.Insert(
		netipx.PrefixIPNet(addr),
		mmdbtype.String(addr.String()),
	)
	if err != nil {
		return fmt.Errorf("inserting ip: %w", err)
	}

	if err := w.write(dbWriter, "MaxMind-DB-no-ipv4-search-tree.mmdb"); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	return nil
}

// WriteNoMapTestDB writes an mmdb file where each record points to
// a string value.
func (w *Writer) WriteNoMapTestDB() error {
	dbWriter, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: "MaxMind DB String Value Entries",
			Description: map[string]string{
				"en": "MaxMind DB String Value Entries (no maps or arrays as values)",
			},
			IPVersion:  4,
			Languages:  []string{"en"},
			RecordSize: 24,
		},
	)
	if err != nil {
		return fmt.Errorf("creating mmdbwriter: %w", err)
	}

	ipRange, err := parseIPRange("1.1.1.1", "1.1.1.32")
	if err != nil {
		return fmt.Errorf("parsing ip range: %w", err)
	}

	for _, prefix := range ipRange.Prefixes() {
		err := dbWriter.Insert(
			netipx.PrefixIPNet(prefix),
			mmdbtype.String(prefix.String()),
		)
		if err != nil {
			return fmt.Errorf("inserting ip: %w", err)
		}
	}

	if err := w.write(dbWriter, "MaxMind-DB-string-value-entries.mmdb"); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	return nil
}

// WriteMetadataPointersTestDB writes an mmdb file with metadata pointers allowed.
func (w *Writer) WriteMetadataPointersTestDB() error {
	repeatedString := "Lots of pointers in metadata"
	dbWriter, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: repeatedString,
			Description: map[string]string{
				"en": repeatedString,
				"es": repeatedString,
				"zh": repeatedString,
			},
			DisableIPv4Aliasing: true,
			IPVersion:           6,
			Languages:           []string{"en", "es", "zh"},
			RecordSize:          24,
		},
	)
	if err != nil {
		return fmt.Errorf("creating mmdbwriter: %w", err)
	}

	if err := populateAllNetworks(dbWriter); err != nil {
		return fmt.Errorf("inserting all networks: %w", err)
	}

	if err := w.write(dbWriter, "MaxMind-DB-test-metadata-pointers.mmdb"); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	return nil
}
