// Package catalogtest builds synthetic vendor catalogs and test signing keys for tests
// and the e2e harness (plan 08 §17). Nothing here is used by the running app.
package catalogtest

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Synthetic system IDs. SystemIDNew matches the iDRAC9 mock (Dell OEM SystemID 2191);
// ModelOld matches the iDRAC8 mock's model, whose BMC reports no system ID.
const (
	SystemIDNew = "088F"
	SystemIDOld = "0627"
	ModelOld    = "PowerEdge R730xd"
)

// comp is one SoftwareComponent of the synthetic catalog.
type comp struct {
	ctype, version, dateTime, crit, name, details, path string
	devices                                             []dev
	systems                                             []sys
	extra                                               string // raw XML inside the component
}

type dev struct {
	cid  string
	pcis [][4]string
}

type sys struct{ id, model string }

var (
	newSys   = sys{SystemIDNew, "R240"}
	oldSys   = sys{SystemIDOld, "R730XD"}
	otherSys = sys{"0890", "T340"}
)

// components are the shapes of the real catalog (plan 08 §4) with made-up versions.
var components = []comp{
	{ctype: "BIOS", version: "2.25.2", dateTime: "2026-09-24T03:00:00-05:00", crit: "1", name: "Dell Server BIOS Version 2.25.2",
		details: "https://www.dell.com/support/home/drivers/driversdetails?driverId=SYN01", path: "FOLDER1/BIOS_SYN01_2.25.2.EXE",
		devices: []dev{{cid: "159"}}, systems: []sys{newSys, otherSys}},
	{ctype: "BIOS", version: "2.21.0", dateTime: "2025-11-02T03:00:00-05:00", crit: "1", name: "Dell Server BIOS Version 2.21.0",
		details: "https://www.dell.com/support/home/drivers/driversdetails?driverId=SYN02", devices: []dev{{cid: "159"}}, systems: []sys{newSys}},
	{ctype: "FRMW", version: "7.00.00.185", dateTime: "2026-08-27T03:00:00-05:00", crit: "2", name: "iDRAC 7.00.00.185",
		details: "https://www.dell.com/support/home/drivers/driversdetails?driverId=SYN03", devices: []dev{{cid: "25227"}}, systems: []sys{newSys}},
	{ctype: "FRMW", version: "23.31.6", dateTime: "2026-05-01T03:00:00-05:00", crit: "1", name: "Broadcom NetXtreme NIC firmware",
		details: "http://www.dell.com/support", devices: []dev{{cid: "105897", pcis: [][4]string{{"14E4", "165F", "1028", "08FF"}, {"14E4", "165F", "1028", "0001"}}}},
		systems: []sys{newSys}},
	{ctype: "FRMW", version: "24.0.0", dateTime: "2026-06-01T03:00:00-05:00", crit: "3", name: "Broadcom NIC firmware, other board",
		devices: []dev{{cid: "105897", pcis: [][4]string{{"14E4", "1639", "1028", "0002"}}}}, systems: []sys{newSys}},
	{ctype: "FRMW", version: "E014", dateTime: "2026-02-10T03:00:00-05:00", crit: "3", name: "SATA drive firmware E014",
		devices: []dev{{cid: "106864"}}, systems: []sys{newSys}},
	{ctype: "FRMW", version: "2.5.13.3025", crit: "1", name: "AHCI controller firmware (only a releaseDate)",
		devices: []dev{{cid: "106883"}}, systems: []sys{newSys}},
	{ctype: "DRVR", version: "99.9.9", dateTime: "2026-07-01T03:00:00-05:00", crit: "2", name: "NIC driver (shares the firmware's component ID)",
		devices: []dev{{cid: "102301"}}, systems: []sys{newSys},
		extra: `<SupportedOperatingSystems><OperatingSystem osCode="W64"><Display lang="en">Windows</Display></OperatingSystem></SupportedOperatingSystems>`},
	{ctype: "APAC", version: "5.0", dateTime: "2026-07-01T03:00:00-05:00", crit: "1", name: "An application", devices: []dev{{cid: "104684"}}, systems: []sys{newSys}},
	{ctype: "FRMW", version: "1.2.3", dateTime: "2026-07-01T03:00:00-05:00", crit: "7", name: "Unknown criticality (skipped)",
		devices: []dev{{cid: "27763"}}, systems: []sys{newSys}},
	{ctype: "FRMW", version: "2.40.40.40", dateTime: "2016-08-19T03:00:00-05:00", crit: "2", name: "iDRAC with Lifecycle Controller 2.40.40.40",
		devices: []dev{{cid: "25227"}}, systems: []sys{oldSys}},
}

// XML is the synthetic catalog as UTF-8 text with a utf-16 prolog (as Encode transcodes it).
func XML() string { return xmlWith(28) }

// Large is a catalog with n filler components (other systems), encoded: for the
// parser's memory bound.
func Large(n int) []byte { return Encode(xmlWith(n)) }

func xmlWith(fillers int) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-16"?>` + "\n")
	b.WriteString(`<Manifest baseLocation="downloads.example.com" dateTime="2026-10-22T14:39:35+05:30" identifier="00000000-0000-4000-8000-000000000001" version="26.10.22" releaseID="SYN01">` + "\n")
	b.WriteString(`<ReleaseNotes><Display lang="en"><![CDATA[Release Notes]]></Display></ReleaseNotes>` + "\n")
	b.WriteString(`<InventoryComponent schemaVersion="3.0" vendorVersion="26.09.00" path="inv.exe"/>` + "\n")
	for _, c := range components {
		writeComp(&b, c)
	}
	for i := range fillers { // filler for other systems: never kept for the fleet
		writeComp(&b, comp{ctype: "FRMW", version: fmt.Sprintf("1.%d.0", i), dateTime: "2026-01-01T00:00:00Z", crit: "3",
			name: fmt.Sprintf("Filler %d", i), devices: []dev{{cid: fmt.Sprint(200000 + i)}},
			systems: []sys{{fmt.Sprintf("%04X", 0x0A00+i%0x1000), fmt.Sprintf("R%d", 900+i)}}})
	}
	b.WriteString(`<SoftwareBundle releaseID="B1" vendorVersion="B.1" path="bundle.xml"><Contents><Package path="x.exe"/></Contents></SoftwareBundle>` + "\n")
	b.WriteString(`<Prerequisites>`)
	writeComp(&b, comp{ctype: "FRMW", version: "9.9.9", dateTime: "2016-01-01T00:00:00Z", crit: "2", name: "A prerequisite, not a release",
		devices: []dev{{cid: "25227"}}, systems: []sys{newSys}})
	b.WriteString("</Prerequisites>\n</Manifest>\n")
	return b.String()
}

func writeComp(b *strings.Builder, c comp) {
	date := fmt.Sprintf(`dateTime="%s"`, c.dateTime)
	if c.dateTime == "" {
		date = `releaseDate="March 3, 2026"`
	}
	fmt.Fprintf(b, `<SoftwareComponent schemaVersion="3.0" vendorVersion="%s" %s path="%s" packageType="LW64" rebootRequired="true">`,
		c.version, date, c.path)
	fmt.Fprintf(b, `<Name><Display lang="fr"><![CDATA[Nom]]></Display><Display lang="en"><![CDATA[%s]]></Display></Name>`, c.name)
	fmt.Fprintf(b, `<ComponentType value="%s"><Display lang="en">x</Display></ComponentType>`, c.ctype)
	b.WriteString(`<Description><Display lang="en"><![CDATA[Fixes & improvements.]]></Display></Description>`)
	b.WriteString(`<SupportedDevices>`)
	for _, d := range c.devices {
		fmt.Fprintf(b, `<Device componentID="%s" embedded="1">`, d.cid)
		for _, p := range d.pcis {
			fmt.Fprintf(b, `<PCIInfo vendorID="%s" deviceID="%s" subVendorID="%s" subDeviceID="%s"/>`, p[0], p[1], p[2], p[3])
		}
		b.WriteString(`<Display lang="en">device</Display><PayloadConfiguration><Image type="FRMW" version="x"/></PayloadConfiguration></Device>`)
	}
	b.WriteString(`</SupportedDevices><SupportedSystems><Brand key="3" prefix="PE"><Display lang="en"><![CDATA[PowerEdge]]></Display>`)
	for _, s := range c.systems {
		fmt.Fprintf(b, `<Model systemID="%s" systemIDType="BIOS"><Display lang="en"><![CDATA[%s]]></Display></Model>`, s.id, s.model)
	}
	b.WriteString(`</Brand></SupportedSystems>`)
	b.WriteString(c.extra)
	fmt.Fprintf(b, `<Criticality value="%s"><Display lang="en">x</Display></Criticality>`, c.crit)
	if c.details != "" {
		fmt.Fprintf(b, `<ImportantInfo URL="%s"><Display lang="en">NA</Display></ImportantInfo>`, c.details)
	}
	b.WriteString(`<RevisionHistory><Display lang="en">NA</Display></RevisionHistory></SoftwareComponent>` + "\n")
}

// Encode returns text as a gzip-compressed UTF-16 LE document with a byte order mark,
// the way Dell publishes its catalog.
func Encode(text string) []byte {
	units := utf16.Encode([]rune(text))
	raw := make([]byte, 0, 2+2*len(units))
	raw = append(raw, 0xFF, 0xFE)
	for _, u := range units {
		raw = binary.LittleEndian.AppendUint16(raw, u)
	}
	return Gzip(raw)
}

// Gzip compresses b as one gzip member.
func Gzip(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// Catalog is the synthetic catalog, encoded.
func Catalog() []byte { return Encode(XML()) }
