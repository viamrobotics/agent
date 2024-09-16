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

func (w *Provisioning) startPortal() error {
	if err := w.startGRPC(); err != nil {
		return errw.Wrap(err, "error starting GRPC service")
	}

	if err := w.startWeb(); err != nil {
		return errw.Wrap(err, "error starting web portal service")
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
	bind := BindAddr + ":80"
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "error listening on: %s", bind)
	}

	w.provisioningWorkers.Add(1)
	go func() {
		defer w.provisioningWorkers.Done()
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

	w.input = &UserInput{}
	w.inputReceived.Store(false)

	return err
}

func (w *Provisioning) GetUserInput() *UserInput {
	if w.inputReceived.Load() {
		w.dataMu.Lock()
		defer w.dataMu.Unlock()
		input := w.input

		// in case both network and device credentials are being updated
		// only send user data after we've had it for ten seconds or if both are already set
		if time.Now().After(input.Updated.Add(time.Second*10)) ||
			(input.SSID != "" && input.PartID != "") ||
			(input.SSID != "" && w.state.getConfigured()) ||
			(input.PartID != "" && w.state.getOnline()) {
			w.input = &UserInput{}
			w.inputReceived.Store(false)
			return input
		}
	}
	return nil
}

func (w *Provisioning) portalIndex(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			w.logger.Error(err)
		}
	}()
	w.state.setLastInteraction()

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	data := templateData{
		Manufacturer: w.cfg.Manufacturer,
		Model:        w.cfg.Model,
		FragmentID:   w.cfg.FragmentID,
		Banner:       w.banner,
		LastNetwork:  w.getLastNetworkTried(),
		VisibleSSIDs: w.getVisibleNetworks(),
		IsOnline:     w.state.getOnline(),
		IsConfigured: w.state.getConfigured(),
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
	w.banner = ""
	w.errors = nil
}

func (w *Provisioning) portalSave(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := req.Body.Close(); err != nil {
			w.logger.Error(err)
		}
	}()

	if req.Method == http.MethodPost {
		w.dataMu.Lock()
		defer w.dataMu.Unlock()
		defer http.Redirect(resp, req, "/", http.StatusSeeOther)

		w.state.setLastInteraction()

		ssid := req.FormValue("ssid")
		psk := req.FormValue("password")
		rawConfig := req.FormValue("viamconfig")

		if ssid == "" && !w.state.getOnline() {
			w.errors = append(w.errors, errors.New("no SSID provided"))
			return
		}

		if rawConfig == "" && !w.state.getConfigured() {
			w.errors = append(w.errors, errors.New("no device config provided"))
			return
		}

		if rawConfig != "" {
			// we'll check if the config is valid, but NOT use the parsed config, in case additional fields are in the json
			cfg := &DeviceConfig{}
			if err := json.Unmarshal([]byte(rawConfig), cfg); err != nil {
				w.errors = append(w.errors, errw.Wrap(err, "invalid json config contents"))
				return
			}
			if cfg.Cloud.ID == "" || cfg.Cloud.Secret == "" || cfg.Cloud.AppAddress == "" {
				w.errors = append(w.errors, errors.New("incomplete cloud config provided"))
				return
			}
			w.input.RawConfig = rawConfig
			w.logger.Debug("saving raw device config")
			w.banner = "Saving device config. "
		}

		if ssid != "" {
			w.input.SSID = ssid
			w.input.PSK = psk
			w.logger.Debugf("saving credentials for %s", w.input.SSID)
			w.banner += "Added credentials for SSID: " + w.input.SSID
		}

		if ssid == w.lastSSID[w.hotspotInterface] && ssid != "" {
			lastNetwork, ok := w.networks[w.lastSSID[w.hotspotInterface]]
			if ok {
				lastNetwork.lastError = nil
			}
		}
		w.input.Updated = time.Now()
		w.inputReceived.Store(true)
	}
}
