package networking

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

type templateData struct {
	Manufacturer string
	Model        string
	FragmentID   string

	Banner       string
	LastNetwork  NetworkInfo
	VisibleSSIDs []NetworkInfo
	Errors       []string
	IsConfigured bool
	IsOnline     bool
}

// portalEntryTemplate is the template executed to render the portal page. Every template set,
// built-in or custom, must define it.
const portalEntryTemplate = "base.html"

//go:embed templates/*
var templates embed.FS

// builtinTemplates are parsed at init so a broken embedded template fails every test run instead
// of surfacing on a device.
var builtinTemplates = template.Must(template.ParseFS(templates, "templates/*.html"))

// parseTemplateDir parses every *.html file directly inside dir.
func parseTemplateDir(dir string) (*template.Template, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errw.Errorf("%s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".html" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	if len(files) == 0 {
		return nil, errw.Errorf("no .html templates found in %s", dir)
	}
	t, err := template.ParseFiles(files...)
	if err != nil {
		return nil, errw.Wrap(err, "parsing templates")
	}
	if t.Lookup(portalEntryTemplate) == nil {
		return nil, errw.Errorf("%s is missing the %s entrypoint template", dir, portalEntryTemplate)
	}
	return t, nil
}

// resolvePortalTemplates picks the templates used to render the portal, in order of preference:
// the configured portal_templates_dir, the development override (only when running locally), then
// the built-in templates. Unusable custom templates are logged and skipped so the portal always
// has a working page.
func (n *Subsystem) resolvePortalTemplates() *template.Template {
	if dir := n.Config().PortalTemplatesDir; dir != "" {
		t, err := parseTemplateDir(dir)
		if err == nil {
			n.logger.Infow("using custom portal templates", "dir", dir)
			return t
		}
		n.logger.Warnw("custom portal templates are unusable, falling back to default templates", "dir", dir, "err", err.Error())
	}

	if utils.IsRunningLocally {
		dir := filepath.Join(utils.ViamDirs.Tmp, "templates")
		t, err := parseTemplateDir(dir)
		if err == nil {
			n.logger.Warnw("running locally, using development portal templates", "dir", dir)
			return t
		}
		n.logger.Debugw("running locally, development portal templates are unusable", "dir", dir, "err", err.Error())
	}

	return builtinTemplates
}

// currentPortalTemplates returns the templates to render a request with: those resolved when the
// web portal started, or freshly resolved on every call when running locally.
func (n *Subsystem) currentPortalTemplates() *template.Template {
	if utils.IsRunningLocally {
		// Re-resolved per request so template edits during development show up on page refresh.
		return n.resolvePortalTemplates()
	}
	n.dataMu.RLock()
	defer n.dataMu.RUnlock()
	if n.portalTemplates == nil {
		return builtinTemplates
	}
	return n.portalTemplates
}

// renderPortal renders the page into memory so nothing reaches the client unless rendering
// succeeds. Templates that parse can still fail at render time (e.g. an unknown field, possibly
// only for some data such as a non-empty error list); in that case the built-in templates are
// rendered instead.
func (n *Subsystem) renderPortal(t *template.Template, data templateData) ([]byte, error) {
	var buf bytes.Buffer
	err := t.ExecuteTemplate(&buf, portalEntryTemplate, data)
	if err == nil || t == builtinTemplates {
		return buf.Bytes(), err
	}

	if n.portalRenderWarned.Swap(t) != t {
		n.logger.Warnw("custom portal templates failed to render, falling back to default templates", "err", err.Error())
	} else {
		n.logger.Debugw("custom portal templates failed to render, falling back to default templates", "err", err.Error())
	}

	buf.Reset()
	if err := builtinTemplates.ExecuteTemplate(&buf, portalEntryTemplate, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *Subsystem) startPortal(bindAddr string) error {
	if err := n.startGRPC(bindAddr, 4772); err != nil {
		return errw.Wrap(err, "starting GRPC service")
	}

	if err := n.startWeb(bindAddr, 80); err != nil {
		return errw.Wrap(err, "starting web portal service")
	}

	return nil
}

func (n *Subsystem) startWeb(bindAddr string, bindPort int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.portalIndex)
	mux.HandleFunc("/save", n.portalSave)

	srv := &http.Server{
		Handler:     mux,
		ReadTimeout: time.Second * 10,
	}
	// Resolved outside dataMu: resolving reads the config, which takes dataMu itself.
	portalTemplates := n.resolvePortalTemplates()
	n.dataMu.Lock()
	n.webServer = srv
	n.portalTemplates = portalTemplates
	n.dataMu.Unlock()
	bind := net.JoinHostPort(bindAddr, strconv.Itoa(bindPort))
	//nolint: noctx
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return errw.Wrapf(err, "cannot bind %s: another service is already using this port. "+
				"Stop it or scope its listen address away from %s (find it with: ss -ltnp | grep :%d)",
				bind, bindAddr, bindPort)
		}
		return errw.Wrapf(err, "listening on: %s", bind)
	}

	n.portalData.workers.Add(1)
	go func() {
		defer utils.Recover(n.logger, func(panickedWith any) {
			n.logger.Warnw("stopping provisioning, panic in web goroutine",
				"panic", panickedWith)
			if err := n.stopProvisioning(); err != nil {
				n.logger.Warnw("failed to stop provisioning", "err", err.Error())
			}
		})
		defer n.portalData.workers.Done()
		err := srv.Serve(lis)
		if !errors.Is(err, http.ErrServerClosed) {
			n.logger.Warn(err)
		}
	}()
	return nil
}

func (n *Subsystem) stopPortal() error {
	n.dataMu.Lock()
	grpcSrv := n.grpcServer
	webSrv := n.webServer
	n.grpcServer = nil
	n.webServer = nil
	n.dataMu.Unlock()

	if grpcSrv != nil {
		grpcSrv.Stop()
	}
	if webSrv != nil {
		return webSrv.Close()
	}
	return nil
}

func (n *Subsystem) portalIndex(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			n.logger.Warn(err)
		}
	}()

	cfg := n.Config()
	t := n.currentPortalTemplates()

	// mu needed to show Errors from portalSave immediately
	n.portalData.mu.Lock()
	defer n.portalData.mu.Unlock()
	data := templateData{
		Manufacturer: cfg.Manufacturer,
		Model:        cfg.Model,
		FragmentID:   cfg.FragmentID,
		Banner:       n.banner.Get(),
		LastNetwork:  n.getLastNetworkTried(),
		VisibleSSIDs: n.getVisibleNetworks(),
		IsOnline:     n.connState.getOnline(),
		IsConfigured: n.connState.getConfigured(),
		Errors:       n.errListAsStrings(),
	}

	page, err := n.renderPortal(t, data)
	if err != nil {
		n.logger.Warn(err)
		http.Error(resp, err.Error(), http.StatusInternalServerError)
	} else {
		resp.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := resp.Write(page); err != nil {
			n.logger.Debugw("writing portal page", "err", err.Error())
		}
	}

	// reset the errors and banner, as they were now just displayed
	n.banner.Set("")
	n.errors.Clear()
}

func (n *Subsystem) portalSave(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			n.logger.Warn(err)
		}
	}()
	defer http.Redirect(resp, req, "/", http.StatusSeeOther)

	if req.Method != http.MethodPost {
		return
	}

	n.connState.setLastInteraction()

	ssid := req.FormValue("ssid")
	psk := req.FormValue("password")
	rawConfig := req.FormValue("viamconfig")

	if ssid == "" && !n.connState.getOnline() {
		n.errors.Add(errors.New("no SSID provided"))
		return
	}

	if rawConfig == "" && !n.connState.getConfigured() {
		n.errors.Add(errors.New("no device config provided"))
		return
	}

	n.portalData.mu.Lock()
	defer n.portalData.mu.Unlock()
	if rawConfig != "" {
		// we'll check if the config is valid, but NOT use the parsed config, in case additional fields are in the json
		cfg := &MachineConfig{}
		if err := json.Unmarshal([]byte(rawConfig), cfg); err != nil {
			n.errors.Add(errw.Wrap(err, "invalid json config contents"))
			return
		}
		if cfg.Cloud == nil {
			n.errors.Add(errors.New("incomplete cloud config provided"))
			return
		}
		if err := cfg.Cloud.IsValid(); err != nil {
			n.errors.Add(err)
			return
		}
		n.portalData.input.RawConfig = rawConfig
		n.logger.Debug("saving raw device config")
		n.banner.Set("Saving device config. ")
	}

	if ssid != "" {
		n.portalData.input.SSID = ssid
		n.portalData.input.PSK = psk
		n.logger.Debugf("saving credentials for %s", n.portalData.input.SSID)
		n.banner.Set(n.banner.Get() + "Added credentials for SSID: " + n.portalData.input.SSID)
	}

	if ssid == n.netState.LastSSID(n.Config().HotspotInterface) && ssid != "" {
		lastNetwork := n.netState.LockingNetwork(n.netState.GenNetKey(NetworkTypeWifi, "", ssid))
		lastNetwork.mu.Lock()
		lastNetwork.lastError = nil
		lastNetwork.mu.Unlock()
	}
	n.portalData.sendInput(req.Context())
}
