package redfish

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

const maxFirmwareItems = bmc.MaxFirmwareMembers

// Inventory reads model/serial/BIOS from the ComputerSystem, BMC model/firmware from the
// Manager and component firmware from UpdateService/FirmwareInventory. Licence data is
// vendor-specific and left empty here.
func (d *Driver) Inventory(ctx context.Context) (bmc.Inventory, error) {
	disc, err := d.discovered(ctx)
	if err != nil {
		return bmc.Inventory{}, err
	}
	res := disc.res
	var sys schemas.ComputerSystem
	if err = d.GetJSON(ctx, res.System, &sys); err != nil {
		return bmc.Inventory{}, err
	}
	mgr, _, err := optional[schemas.Manager](ctx, d, res.Manager)
	if err != nil {
		return bmc.Inventory{}, err
	}
	fw, err := d.firmware(ctx, res.FirmwareInventory)
	if err != nil {
		return bmc.Inventory{}, err
	}
	return bmc.NewInventory(bmc.InventoryParams{
		InventoryInfo: inventoryInfo(sys, mgr),
		Firmware:      fw,
	}), nil
}

func inventoryInfo(sys schemas.ComputerSystem, mgr schemas.Manager) bmc.InventoryInfo {
	return bmc.InventoryInfo{
		Manufacturer:      clean(sys.Manufacturer),
		Model:             clean(sys.Model),
		SerialNumber:      clean(sys.SerialNumber),
		SKU:               clean(sys.SKU),
		BIOSVersion:       clean(sys.BiosVersion),
		BMCModel:          clean(mgr.Model),
		BMCFirmware:       clean(mgr.FirmwareVersion),
		MemoryGiB:         bmc.ReadingFrom(sys.MemorySummary.TotalSystemMemoryGiB).Value,
		ProcessorCount:    int(bmc.ReadingFrom(sys.ProcessorSummary.Count).Value),
		ProcessorModel:    clean(sys.ProcessorSummary.Model),
		LogicalProcessors: int(bmc.ReadingFrom(sys.ProcessorSummary.LogicalProcessorCount).Value),
		SystemID:          dellSystemID(sys.OEM),
	}
}

// dellSystemID reads Oem.Dell.DellSystem.SystemID (iDRAC9 and later) as the four hex
// digits Dell's catalog uses; anything else (no Oem block, out of range) is "".
func dellSystemID(oem json.RawMessage) string {
	var o struct {
		Dell struct {
			DellSystem struct {
				SystemID *int `json:"SystemID"`
			} `json:"DellSystem"`
		} `json:"Dell"`
	}
	if len(oem) == 0 || json.Unmarshal(oem, &o) != nil {
		return ""
	}
	id := o.Dell.DellSystem.SystemID
	if id == nil || *id <= 0 || *id > 0xFFFF {
		return ""
	}
	return fmt.Sprintf("%04X", *id)
}

// firmware lists component firmware. An OEM parser may derive it from member IDs;
// otherwise each member (bounded) is fetched and absent members are skipped.
func (d *Driver) firmware(ctx context.Context, uri string) ([]bmc.FirmwareItem, error) {
	members, err := d.optionalMembers(ctx, uri, maxFirmwareItems)
	if err != nil || len(members) == 0 {
		return nil, err
	}
	if d.opts.fwParser != nil {
		if items, ok := d.opts.fwParser(members); ok {
			return items, nil
		}
	}
	var out []bmc.FirmwareItem
	for _, m := range members {
		sw, found, err := optional[schemas.SoftwareInventory](ctx, d, m)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, bmc.FirmwareItem{ID: clean(sw.ID), Name: clean(sw.Name), Version: clean(sw.Version)})
		}
	}
	return out, nil
}
