package redfish

import (
	"encoding/json"
	"strings"
)

// Minimal views of Redfish documents for link discovery. Typed sensor data is
// decoded with gofish schemas; these only carry the links gofish keeps unexported.

type odataRef struct {
	ID string `json:"@odata.id"`
}

type collectionDoc struct {
	Members  []odataRef `json:"Members"`
	Count    *int       `json:"Members@odata.count"`
	NextLink string     `json:"Members@odata.nextLink"`
}

func (c collectionDoc) uris() []string {
	out := make([]string, 0, len(c.Members))
	for _, m := range c.Members {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out
}

type rootDoc struct {
	RedfishVersion string   `json:"RedfishVersion"`
	Product        string   `json:"Product"`
	Systems        odataRef `json:"Systems"`
	Chassis        odataRef `json:"Chassis"`
	Managers       odataRef `json:"Managers"`
	UpdateService  odataRef `json:"UpdateService"`
	LicenseService odataRef `json:"LicenseService"`
	AccountService odataRef `json:"AccountService"`
}

type systemLinksDoc struct {
	Links struct {
		Chassis   []odataRef `json:"Chassis"`
		ManagedBy []odataRef `json:"ManagedBy"`
	} `json:"Links"`
	Actions struct {
		Reset struct {
			Allowable []string `json:"ResetType@Redfish.AllowableValues"`
		} `json:"#ComputerSystem.Reset"`
	} `json:"Actions"`
}

type chassisLinksDoc struct {
	Thermal          odataRef `json:"Thermal"`
	Power            odataRef `json:"Power"`
	ThermalSubsystem odataRef `json:"ThermalSubsystem"`
	PowerSubsystem   odataRef `json:"PowerSubsystem"`
}

type managerLinksDoc struct {
	LogServices odataRef `json:"LogServices"`
}

// managerResetAction is the Manager's #Manager.Reset action (BMC restart).
type managerResetAction struct {
	Target    string   `json:"target"`
	Allowable []string `json:"ResetType@Redfish.AllowableValues"`
}

type updateServiceDoc struct {
	FirmwareInventory odataRef `json:"FirmwareInventory"`
}

type thermalSubsystemDoc struct {
	Fans           odataRef `json:"Fans"`
	ThermalMetrics odataRef `json:"ThermalMetrics"`
}

type powerSubsystemDoc struct {
	PowerSupplies odataRef `json:"PowerSupplies"`
}

// flexString accepts a string, null, or the iDRAC8 quirk [{"Member": "x"}, ...].
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexString(s)
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		*f = ""
		return nil //nolint:nilerr // tolerate any other shape as empty
	}
	parts := make([]string, 0, len(arr))
	for _, raw := range arr {
		var m struct {
			Member string `json:"Member"`
		}
		if json.Unmarshal(raw, &m) == nil && m.Member != "" {
			parts = append(parts, m.Member)
			continue
		}
		var p string
		if json.Unmarshal(raw, &p) == nil && p != "" {
			parts = append(parts, p)
		}
	}
	*f = flexString(strings.Join(parts, ", "))
	return nil
}

type logEntryDoc struct {
	ID         flexString `json:"Id"`
	Created    flexString `json:"Created"`
	Severity   flexString `json:"Severity"`
	Message    flexString `json:"Message"`
	MessageID  flexString `json:"MessageId"`
	EntryType  flexString `json:"EntryType"`
	EntryCode  flexString `json:"EntryCode"`
	SensorType flexString `json:"SensorType"`
}

type logPageDoc struct {
	Members  []logEntryDoc `json:"Members"`
	Count    *int          `json:"Members@odata.count"`
	NextLink string        `json:"Members@odata.nextLink"`
}
