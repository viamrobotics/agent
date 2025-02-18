package provisioning

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"time"

	errw "github.com/pkg/errors"
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

//go:embed templates/*
var templates embed.FS

func (w *Provisioning) startPortal(inputChan chan<- userInput) error {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	w.portalData = &portalData{input: &userInput{}, inputChan: inputChan}

	if err := w.startGRPC(); err != nil {
		return errw.Wrap(err, "starting GRPC service")
	}

	if err := w.startWeb(); err != nil {
		return errw.Wrap(err, "starting web portal service")
	}

	return nil
}

func (w *Provisioning) startWeb() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", w.portalIndex)
	mux.HandleFunc("/save", w.portalSave)
	w.webServer = &http.Server{
		Handler:     mux,
		ReadTimeout: time.Second * 10,
	}
	bind := PortalBindAddr + ":80"
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "listening on: %s", bind)
	}

	w.portalData.workers.Add(1)
	go func() {
		defer w.portalData.workers.Done()
		err := w.webServer.Serve(lis)
		if !errors.Is(err, http.ErrServerClosed) {
			w.logger.Error(err)
		}
	}()
	return nil
}

func (w *Provisioning) stopPortal() error {
	if w.grpcServer != nil {
		w.grpcServer.Stop()
		w.grpcServer = nil
	}

	var err error
	if w.webServer != nil {
		err = w.webServer.Close()
	}

	w.portalData.mu.Lock()
	defer w.portalData.mu.Unlock()
	if w.portalData.cancel != nil {
		w.portalData.cancel()
	}
	w.portalData.workers.Wait()
	w.portalData = &portalData{input: &userInput{}}

	return err
}

func (w *Provisioning) portalIndex(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			w.logger.Error(err)
		}
	}()
	w.connState.setLastInteraction()

	cfg := w.Config()

	data := templateData{
		Manufacturer: cfg.Manufacturer,
		Model:        cfg.Model,
		FragmentID:   cfg.FragmentID,
		Banner:       w.banner.Get(),
		LastNetwork:  w.getLastNetworkTried(),
		VisibleSSIDs: w.getVisibleNetworks(),
		IsOnline:     w.connState.getOnline(),
		IsConfigured: w.connState.getConfigured(),
		Errors:       w.errListAsStrings(),
	}

	t, err := template.ParseFS(templates, "templates/*.html")
	if err != nil {
		w.logger.Error(err)
		http.Error(resp, err.Error(), http.StatusInternalServerError)
	}

	if os.Getenv("VIAM_AGENT_DEVMODE") != "" {
		w.logger.Warn("devmode enabled, using templates from /opt/viam/tmp/templates/")
		newT, err := template.ParseGlob("/opt/viam/tmp/templates/*.html")
		if err == nil {
			t = newT
		}
	}

	err = t.Execute(resp, data)
	if err != nil {
		w.logger.Error(err)
		http.Error(resp, err.Error(), http.StatusInternalServerError)
	}

	// reset the errors and banner, as they were now just displayed
	w.banner.Set("")
	w.errors.Clear()
}

func (w *Provisioning) portalSave(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			w.logger.Error(err)
		}
	}()
	defer http.Redirect(resp, req, "/", http.StatusSeeOther)

	if req.Method != http.MethodPost {
		return
	}

	w.connState.setLastInteraction()

	ssid := req.FormValue("ssid")
	psk := req.FormValue("password")
	rawConfig := req.FormValue("viamconfig")

	if ssid == "" && !w.connState.getOnline() {
		w.errors.Add(errors.New("no SSID provided"))
		return
	}

	if rawConfig == "" && !w.connState.getConfigured() {
		w.errors.Add(errors.New("no device config provided"))
		return
	}

	w.portalData.mu.Lock()
	defer w.portalData.mu.Unlock()
	if rawConfig != "" {
		// we'll check if the config is valid, but NOT use the parsed config, in case additional fields are in the json
		cfg := &MachineConfig{}
		if err := json.Unmarshal([]byte(rawConfig), cfg); err != nil {
			w.errors.Add(errw.Wrap(err, "invalid json config contents"))
			return
		}
		if cfg.Cloud.ID == "" || cfg.Cloud.Secret == "" || cfg.Cloud.AppAddress == "" {
			w.errors.Add(errors.New("incomplete cloud config provided"))
			return
		}
		w.portalData.input.RawConfig = rawConfig
		w.logger.Debug("saving raw device config")
		w.banner.Set("Saving device config. ")
	}

	if ssid != "" {
		w.portalData.input.SSID = ssid
		w.portalData.input.PSK = psk
		w.logger.Debugf("saving credentials for %s", w.portalData.input.SSID)
		w.banner.Set(w.banner.Get() + "Added credentials for SSID: " + w.portalData.input.SSID)
	}

	if ssid == w.netState.LastSSID(w.Config().HotspotInterface) && ssid != "" {
		lastNetwork := w.netState.LockingNetwork(w.Config().HotspotInterface, ssid)
		lastNetwork.mu.Lock()
		lastNetwork.lastError = nil
		lastNetwork.mu.Unlock()
	}
	w.portalData.Updated = time.Now()
	w.portalData.sendInput(w.connState)
}
