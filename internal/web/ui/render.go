package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Page template names (templates/<name>.html).
const (
	pageLogin        = "login"
	pageTOTP         = "totp"
	pageEnroll       = "enroll"
	pageEnrollReveal = "enroll_reveal"
	pageSetup        = "setup"
	pageOverview     = "overview"
	pageServer       = "server"
	pageLogs         = "logs"
	pageInventory    = "inventory"
	pageError        = "error"
	pageServers      = "servers"
	pageEvents       = "events"
	pageAbout        = "about"
	pageStepUp       = "stepup"
	pageEnrolLink    = "enroll_link"
	pageConsole      = "console"
	pageSerial       = "serial"
	pageKVMLaunch    = "kvm_launch"
	pageSensors      = "sensors"
	pageActivity     = "activity"
	pageSrvActivity  = "server_activity"
	pageFan          = "fan"
	pageHelp         = "help"
	pageConfirm      = "confirm"
	pageSecurity     = "security"
	pageMaintNew     = "maint_new"
	pageNoteForm     = "note_form"
	pageFirmware     = "firmware"
	pageHistory      = "history"
	pageGo           = "go"

	pageSettingsUsers   = "settings_users"
	pageSettingsUser    = "settings_user"
	pageSettingsTokens  = "settings_tokens"
	pageSettingsAudit   = "settings_audit"
	pageSettingsReveal  = "settings_reveal"
	pageSettingsGeneral = "settings_general"
	pageDisplay         = "display"

	pageSettingsServers    = "settings_servers"
	pageSettingsServer     = "settings_server"
	pageSettingsServerNew  = "settings_server_new"
	pageSettingsServerTOFU = "settings_server_tofu"
	pageSettingsNotify     = "settings_notify"
	pageSettingsNotifyForm = "settings_notify_form"
	// Settings → Integrations (slice S4, tech_doc §34).
	pageSettingsIntegrations = "settings_integrations"
	pageSettingsGELFTOFU     = "settings_integrations_tofu"
)

func pageNames() []string {
	return []string{pageLogin, pageTOTP, pageEnroll, pageEnrollReveal, pageSetup, pageOverview,
		pageServer, pageLogs, pageInventory, pageError, pageServers, pageEvents, pageAbout, pageStepUp,
		pageEnrolLink, pageConsole, pageSerial, pageKVMLaunch, pageSensors, pageActivity, pageSrvActivity, pageFan, pageHelp, pageConfirm, pageSecurity, pageMaintNew, pageNoteForm, pageFirmware, pageHistory, pageGo, pageSettingsUsers, pageSettingsUser, pageSettingsTokens, pageSettingsAudit, pageSettingsReveal, pageSettingsGeneral, pageDisplay,
		pageSettingsServers, pageSettingsServer, pageSettingsServerNew, pageSettingsServerTOFU,
		pageSettingsNotify, pageSettingsNotifyForm, pageSettingsIntegrations, pageSettingsGELFTOFU}
}

// renderer holds one parsed template set per page (layout + partials + page), built
// once at startup; template sets are read-only afterwards.
type renderer struct {
	pages map[string]*template.Template
}

func newRenderer() (*renderer, error) {
	sprite, _, err := buildSprite(iconFS, staticFS)
	if err != nil {
		return nil, err
	}
	funcs := template.FuncMap{"trimUnit": trimUnit, "sprite": func() template.HTML { return sprite }}
	pages := make(map[string]*template.Template, len(pageNames()))
	for _, name := range pageNames() {
		t, err := template.New("layout").Funcs(funcs).ParseFS(templateFS,
			"templates/layout.html", "templates/partials.html", "templates/*_partials.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("ui: parse template %s: %w", name, err)
		}
		pages[name] = t
	}
	return &renderer{pages: pages}, nil
}

// render executes into a buffer first, so a template error produces a clean 500
// instead of a half-written page.
func (rd *renderer) render(w http.ResponseWriter, status int, name string, data layoutData) error {
	t, ok := rd.pages[name]
	if !ok {
		return fmt.Errorf("ui: unknown page %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		return fmt.Errorf("ui: render %s: %w", name, err)
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, err := w.Write(buf.Bytes())
	return err
}

// staticCacheControl lets browsers keep the embedded assets for an hour instead of
// refetching them on every page (UI review F-19); the stylesheet URL carries the
// version, so an upgrade is picked up at once.
const staticCacheControl = "public, max-age=3600"

// fontCacheControl: the vendored fonts carry their version in the directory name
// (static/vendor/fonts/<family>-<version>/), so one URL never changes content and can be
// cached for a year without a ?v= fingerprint (which the sign-in page must not show).
const fontCacheControl = "public, max-age=31536000, immutable"

const fontPrefix = "/static/vendor/fonts/"

// staticHandler serves the embedded stylesheet and images. Only GET/HEAD reach it
// (route pattern).
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // the embed directive guarantees the directory exists
	}
	files := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, fontPrefix) && strings.HasSuffix(r.URL.Path, ".woff2") {
			w.Header().Set("Cache-Control", fontCacheControl)
			w.Header().Set("Content-Type", "font/woff2") // not in every mime table (distroless has none)
		} else {
			w.Header().Set("Cache-Control", staticCacheControl)
		}
		files.ServeHTTP(w, r)
	})
}
