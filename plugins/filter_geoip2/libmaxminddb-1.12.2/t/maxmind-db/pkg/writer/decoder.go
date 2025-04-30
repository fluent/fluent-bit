package writer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net/netip"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"go4.org/netipx"
)

// WriteDecoderTestDB writes an mmdb file with all possible record value types.
func (w *Writer) WriteDecoderTestDB() error {
	dbWriter, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: "MaxMind DB Decoder Test",
			Description: map[string]string{
				"en": "MaxMind DB Decoder Test database - contains every MaxMind DB data type",
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
	if err := insertAllTypes(dbWriter, addrs); err != nil {
		return fmt.Errorf("inserting all types records: %w", err)
	}

	zeroAddr, err := netip.ParsePrefix("::0.0.0.0/128")
	if err != nil {
		return fmt.Errorf("parsing ip: %w", err)
	}
	if err := insertAllTypesZero(dbWriter, []netip.Prefix{zeroAddr}); err != nil {
		return fmt.Errorf("inserting all types records: %w", err)
	}

	maxAddr, err := netip.ParsePrefix("::255.255.255.255/128")
	if err != nil {
		return fmt.Errorf("parsing ip: %w", err)
	}
	if err := insertNumericMax(dbWriter, []netip.Prefix{maxAddr}); err != nil {
		return fmt.Errorf("inserting all types records: %w", err)
	}

	if err := w.write(dbWriter, "MaxMind-DB-test-decoder.mmdb"); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	return nil
}

// insertAllTypes inserts records with all possible value types.
func insertAllTypes(w *mmdbwriter.Tree, ipAddresses []netip.Prefix) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint32(42)); err != nil {
		return fmt.Errorf("creating buffer for all types record: %w", err)
	}

	ui64 := big.Int{}
	ui64.Lsh(big.NewInt(1), 60)

	ui128 := big.Int{}
	ui128.Lsh(big.NewInt(1), 120)
	mmdbUint128 := mmdbtype.Uint128(ui128)

	allTypes := mmdbtype.Map{
		"array": mmdbtype.Slice{
			mmdbtype.Uint32(1),
			mmdbtype.Uint32(2),
			mmdbtype.Uint32(3),
		},
		"bytes":   mmdbtype.Bytes(buf.Bytes()),
		"boolean": mmdbtype.Bool(true),
		"double":  mmdbtype.Float64(42.123456),
		"float":   mmdbtype.Float32(1.1),
		"int32":   mmdbtype.Int32(-1 * math.Pow(2, 28)),
		"map": mmdbtype.Map{
			"mapX": mmdbtype.Map{
				"utf8_stringX": mmdbtype.String("hello"),
				"arrayX": mmdbtype.Slice{
					mmdbtype.Uint32(7),
					mmdbtype.Uint32(8),
					mmdbtype.Uint32(9),
				},
			},
		},
		"uint16":      mmdbtype.Uint16(100),
		"uint32":      mmdbtype.Uint32(math.Pow(2, 28)),
		"uint64":      mmdbtype.Uint64(ui64.Uint64()),
		"uint128":     mmdbUint128.Copy(),
		"utf8_string": mmdbtype.String("unicode! ☯ - ♫"),
	}

	for _, addr := range ipAddresses {
		err := w.Insert(
			netipx.PrefixIPNet(addr),
			allTypes,
		)
		if err != nil {
			return fmt.Errorf("inserting ip: %w", err)
		}
	}
	return nil
}

// insertAllTypesZero inserts records with all possible value types with zero values.
func insertAllTypesZero(w *mmdbwriter.Tree, ipAddresses []netip.Prefix) error {
	var uint128 big.Int
	mmdbUint128 := mmdbtype.Uint128(uint128)

	zeroValues := mmdbtype.Map{
		"array":       mmdbtype.Slice{},
		"bytes":       mmdbtype.Bytes([]byte{}),
		"boolean":     mmdbtype.Bool(false),
		"double":      mmdbtype.Float64(0),
		"float":       mmdbtype.Float32(0),
		"int32":       mmdbtype.Int32(0),
		"map":         mmdbtype.Map{},
		"uint16":      mmdbtype.Uint16(0),
		"uint32":      mmdbtype.Uint32(0),
		"uint64":      mmdbtype.Uint64(0),
		"uint128":     mmdbUint128.Copy(),
		"utf8_string": mmdbtype.String(""),
	}

	for _, addr := range ipAddresses {
		err := w.Insert(
			netipx.PrefixIPNet(addr),
			zeroValues,
		)
		if err != nil {
			return fmt.Errorf("inserting ip: %w", err)
		}
	}
	return nil
}

// insertNumericMax inserts records with numeric types maxed out.
func insertNumericMax(w *mmdbwriter.Tree, ipAddresses []netip.Prefix) error {
	var uint128Max big.Int
	uint128Max.Exp(big.NewInt(2), big.NewInt(128), nil)
	uint128Max.Sub(&uint128Max, big.NewInt(1))
	mmdbUint128 := mmdbtype.Uint128(uint128Max)

	numMax := mmdbtype.Map{
		"double":  mmdbtype.Float64(math.Inf(1)),
		"float":   mmdbtype.Float32(float32(math.Inf(1))),
		"int32":   mmdbtype.Int32(1<<31 - 1),
		"uint16":  mmdbtype.Uint16(0xffff),
		"uint32":  mmdbtype.Uint32(0xffffffff),
		"uint64":  mmdbtype.Uint64(0xffffffffffffffff),
		"uint128": mmdbUint128.Copy(),
	}

	for _, addr := range ipAddresses {
		err := w.Insert(
			netipx.PrefixIPNet(addr),
			numMax,
		)
		if err != nil {
			return fmt.Errorf("inserting ip: %w", err)
		}
	}
	return nil
}
