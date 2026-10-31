package redfish

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

// Resources are the URIs discovered by a probe. An empty string means "not offered".
type Resources struct {
	System            string
	Chassis           string
	Manager           string
	Thermal           string
	Power             string
	ThermalSubsystem  string
	PowerSubsystem    string
	SELEntries        string
	FirmwareInventory string
	LicenseService    string
	AccountService    string
	logServices       []string
}

// LogServices returns a copy of the manager's LogService member URIs.
func (r Resources) LogServices() []string { return slices.Clone(r.logServices) }

type discovery struct {
	res  Resources
	caps bmc.Capabilities
}

// Probe discovers the BMC's resources and capabilities and caches them for later calls.
func (d *Driver) Probe(ctx context.Context) (bmc.Capabilities, error) {
	disc, err := d.discover(ctx)
	if err != nil {
		return bmc.Capabilities{}, err
	}
	d.disc.Store(disc)
	return disc.caps, nil
}

// Resources returns the cached discovery, probing first if needed.
func (d *Driver) Resources(ctx context.Context) (Resources, error) {
	disc, err := d.discovered(ctx)
	if err != nil {
		return Resources{}, err
	}
	return disc.res, nil
}

// Capabilities returns the cached probe result, probing first if needed.
func (d *Driver) Capabilities(ctx context.Context) (bmc.Capabilities, error) {
	disc, err := d.discovered(ctx)
	if err != nil {
		return bmc.Capabilities{}, err
	}
	return disc.caps, nil
}

func (d *Driver) discovered(ctx context.Context) (*discovery, error) {
	if disc := d.disc.Load(); disc != nil {
		return disc, nil
	}
	disc, err := d.discover(ctx)
	if err != nil {
		return nil, err
	}
	d.disc.Store(disc)
	return disc, nil
}

func (d *Driver) discover(ctx context.Context) (*discovery, error) {
	var root rootDoc
	if err := d.GetJSON(ctx, serviceRoot, &root); err != nil {
		return nil, err
	}
	sysURI, err := d.firstMember(ctx, root.Systems.ID)
	if err != nil {
		return nil, fmt.Errorf("discover system: %w", err)
	}
	if sysURI == "" {
		return nil, fmt.Errorf("discover system: %w: no ComputerSystem", bmc.ErrUnsupported)
	}
	var sys systemLinksDoc
	if err = d.GetJSON(ctx, sysURI, &sys); err != nil {
		return nil, err
	}
	res, mgr, err := d.discoverResources(ctx, root, sysURI, sys)
	if err != nil {
		return nil, err
	}
	flags := capabilityFlags(root, res, mgr.Manager, d.opts.now())
	flags.ManagerReset, flags.BMCLastReset = managerResetOffered(res.Manager, mgr.reset), parseLastReset(mgr.lastReset)
	caps := bmc.NewCapabilities(bmc.CapabilityParams{
		Flags:             flags,
		ResetTypes:        sys.Actions.Reset.Allowable,
		ManagerResetTypes: mgr.reset.Allowable,
	})
	return &discovery{res: res, caps: caps}, nil
}

func (d *Driver) discoverResources(ctx context.Context, root rootDoc, sysURI string, sys systemLinksDoc) (Resources, managerFacts, error) {
	chassisURI, err := d.linkOrFirst(ctx, sys.Links.Chassis, root.Chassis.ID)
	if err != nil {
		return Resources{}, managerFacts{}, err
	}
	managerURI, err := d.linkOrFirst(ctx, sys.Links.ManagedBy, root.Managers.ID)
	if err != nil {
		return Resources{}, managerFacts{}, err
	}
	ch, _, err := optional[chassisLinksDoc](ctx, d, chassisURI)
	if err != nil {
		return Resources{}, managerFacts{}, err
	}
	mgr, err := d.discoverManager(ctx, managerURI)
	if err != nil {
		return Resources{}, managerFacts{}, err
	}
	logs := mgr.logs
	sel, err := d.findSEL(ctx, managerURI, logs)
	if err != nil {
		return Resources{}, managerFacts{}, err
	}
	fw, err := d.findFirmwareInventory(ctx, root.UpdateService.ID)
	if err != nil {
		return Resources{}, managerFacts{}, err
	}
	return Resources{
		System: sysURI, Chassis: chassisURI, Manager: managerURI,
		Thermal: ch.Thermal.ID, Power: ch.Power.ID,
		ThermalSubsystem: ch.ThermalSubsystem.ID, PowerSubsystem: ch.PowerSubsystem.ID,
		SELEntries: sel, FirmwareInventory: fw, LicenseService: root.LicenseService.ID, AccountService: root.AccountService.ID,
		logServices: logs,
	}, mgr, nil
}

// optional GETs uri into a T. found is false (and err nil) when the BMC does not offer it.
func optional[T any](ctx context.Context, d *Driver, uri string) (out T, found bool, err error) {
	if uri == "" {
		return out, false, nil
	}
	if err := d.GetJSON(ctx, uri, &out); err != nil {
		var zero T
		if isAbsent(err) {
			return zero, false, nil
		}
		return zero, false, err
	}
	return out, true, nil
}

func (d *Driver) firstMember(ctx context.Context, collectionURI string) (string, error) {
	col, _, err := optional[collectionDoc](ctx, d, collectionURI)
	if err != nil {
		return "", err
	}
	if uris := col.uris(); len(uris) > 0 {
		return uris[0], nil
	}
	return "", nil
}

func (d *Driver) linkOrFirst(ctx context.Context, links []odataRef, collectionURI string) (string, error) {
	for _, l := range links {
		if l.ID != "" {
			return l.ID, nil
		}
	}
	return d.firstMember(ctx, collectionURI)
}

// managerFacts is what discovery reads from the Manager document: the typed manager,
// its LogService members, the #Manager.Reset action and LastResetTime (raw).
type managerFacts struct {
	schemas.Manager
	logs      []string
	reset     managerResetAction
	lastReset string
}

func (d *Driver) discoverManager(ctx context.Context, uri string) (managerFacts, error) {
	if uri == "" {
		return managerFacts{}, nil
	}
	body, err := d.get(ctx, uri)
	if isAbsent(err) {
		return managerFacts{}, nil
	}
	if err != nil {
		return managerFacts{}, err
	}
	var mgr schemas.Manager
	var links managerLinksDoc
	if err = decode(uri, withoutManagerExtras(body), &mgr); err != nil {
		return managerFacts{}, err
	}
	if err = decode(uri, body, &links); err != nil {
		return managerFacts{}, err
	}
	col, _, err := optional[collectionDoc](ctx, d, links.LogServices.ID)
	if err != nil {
		return managerFacts{}, err
	}
	reset, last := managerExtras(body)
	return managerFacts{Manager: mgr, logs: col.uris(), reset: reset, lastReset: last}, nil
}

// findSEL returns the first SEL entries collection that answers: the standard
// LogServices/<..Sel>/Entries, then any OEM fallbacks.
func (d *Driver) findSEL(ctx context.Context, managerURI string, logServices []string) (string, error) {
	var candidates []string
	for _, ls := range logServices {
		if strings.HasSuffix(strings.ToLower(ls), "/sel") {
			candidates = append(candidates, ls+"/Entries")
		}
	}
	if d.opts.selFallbacks != nil && managerURI != "" {
		candidates = append(candidates, d.opts.selFallbacks(managerURI)...)
	}
	for _, c := range candidates {
		var col logPageDoc
		err := d.GetJSON(ctx, c, &col)
		if err == nil {
			return c, nil
		}
		if !isAbsent(err) {
			return "", err
		}
	}
	return "", nil
}

func (d *Driver) findFirmwareInventory(ctx context.Context, updateService string) (string, error) {
	if updateService == "" {
		return "", nil
	}
	us, _, err := optional[updateServiceDoc](ctx, d, updateService)
	if err != nil {
		return "", err
	}
	uri := us.FirmwareInventory.ID
	if uri == "" {
		uri = updateService + "/FirmwareInventory" // DSP0268 well-known location
	}
	_, found, err := optional[collectionDoc](ctx, d, uri)
	if err != nil || !found {
		return "", err
	}
	return uri, nil
}
