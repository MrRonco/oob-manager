package firmware

import (
	"testing"

	"oob-manager/internal/bmc"
)

func TestKindFromName(t *testing.T) {
	cases := map[string]bmc.FirmwareKind{
		"BIOS":                                bmc.FirmwareBIOS,
		"System BIOS":                         bmc.FirmwareBIOS,
		"Integrated Remote Access Controller": bmc.FirmwareBMC,
		"BMC Firmware":                        bmc.FirmwareBMC,
		"System CPLD":                         bmc.FirmwareCPLD,
		"Backplane 0":                         bmc.FirmwareEnclosure,
		"Drive Enclosure 1":                   bmc.FirmwareEnclosure,
		"Power Supply.Slot.1":                 bmc.FirmwarePSU,
		"PSU 2":                               bmc.FirmwarePSU,
		"Broadcom Gigabit Ethernet BCM5720 - 00:00:5E:00:53:00": bmc.FirmwareNIC,
		"Intel(R) Ethernet Converged Network Adapter X710":      bmc.FirmwareNIC,
		"Disk 0 in Backplane 1 of RAID Controller 1":            bmc.FirmwareDrive, // the drive keyword is checked first: it names the device
		"Disk 0":                    bmc.FirmwareDrive,
		"SAS SSD 1":                 bmc.FirmwareDrive,
		"NVMe drive":                bmc.FirmwareDrive,
		"RAID Controller in Slot 1": bmc.FirmwareStorage,
		"Storage Controller":        bmc.FirmwareStorage,
		"Something else":            "",
		"":                          "",
	}
	for name, want := range cases {
		if got := KindFromName(name); got != want {
			t.Errorf("KindFromName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestKindFromRelated(t *testing.T) {
	cases := map[string]bmc.FirmwareKind{
		"/redfish/v1/Managers/bmc":                                 bmc.FirmwareBMC,
		"/redfish/v1/Systems/1":                                    bmc.FirmwareBIOS,
		"/redfish/v1/Systems/1/Bios":                               bmc.FirmwareBIOS,
		"/redfish/v1/Systems/1/EthernetInterfaces/eth0":            bmc.FirmwareNIC,
		"/redfish/v1/Chassis/1/NetworkAdapters/nic1":               bmc.FirmwareNIC,
		"/redfish/v1/Systems/1/Storage/RAID1/Drives/0":             bmc.FirmwareDrive,
		"/redfish/v1/Chassis/1/Drives/0":                           bmc.FirmwareDrive,
		"/redfish/v1/Systems/1/Storage/RAID1":                      bmc.FirmwareStorage,
		"/redfish/v1/Systems/1/Storage/RAID1/StorageControllers/0": bmc.FirmwareStorage,
		"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/0":     bmc.FirmwarePSU,
		"/redfish/v1/Chassis/1/Power#/PowerSupplies/0":             bmc.FirmwarePSU,
		"/redfish/v1/Chassis/Enclosure1":                           bmc.FirmwareEnclosure,
		"/redfish/v1/Systems/1/Processors/CPU0":                    bmc.FirmwareOther,
		"/redfish/v1/UpdateService":                                "",
		"":                                                         "",
	}
	for uri, want := range cases {
		if got := KindFromRelated(uri); got != want {
			t.Errorf("KindFromRelated(%q) = %q, want %q", uri, got, want)
		}
	}
}
