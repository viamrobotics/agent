package networking

import (
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestWebPortalJsonParse(t *testing.T) {
	bindAddr := "localhost"
	bindPort := 8081
	httpSaveURL := fmt.Sprintf("http://%s/save", net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)))

	inputChan := make(chan userInput, 1)
	logger := logging.NewTestLogger(t)
	n := Subsystem{
		portalData: &userInputData{input: &userInput{}, inputChan: inputChan, connState: NewConnectionState(logger)},
		logger:     logger,
		connState:  NewConnectionState(logger),
		netState:   &networkState{},
		banner:     &banner{},
		errors:     &errorList{},
	}
	err := n.startWeb(bindAddr, bindPort)
	defer func() {
		err = n.webServer.Close()
		test.That(t, err, test.ShouldBeNil)
	}()
	test.That(t, err, test.ShouldBeNil)

	// Test json missing cloud section
	client := &http.Client{}
	dummyCtx := t.Context()
	urlParams := url.Values{"ssid": {"notused"}, "password": {"notused"}, "viamconfig": {"{}"}}
	req, err := http.NewRequestWithContext(dummyCtx, http.MethodPost, fmt.Sprintf("%s?%s", httpSaveURL, urlParams.Encode()), nil)
	test.That(t, err, test.ShouldBeNil)
	resp, err := client.Do(req)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, resp.StatusCode, test.ShouldEqual, 200)
	test.That(t, err, test.ShouldBeNil)
	body, err := io.ReadAll(resp.Body)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, strings.Contains(string(body), "incomplete cloud config provided"), test.ShouldBeTrue)
	err = resp.Body.Close()
	test.That(t, err, test.ShouldBeNil)

	// Test malformed json
	client = &http.Client{}
	dummyCtx = t.Context()
	urlParams = url.Values{"ssid": {"notused"}, "password": {"notused"}, "viamconfig": {"{{{"}}
	req, err = http.NewRequestWithContext(dummyCtx, http.MethodPost, fmt.Sprintf("%s?%s", httpSaveURL, urlParams.Encode()), nil)
	test.That(t, err, test.ShouldBeNil)
	resp, err = client.Do(req)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, resp.StatusCode, test.ShouldEqual, 200)
	test.That(t, err, test.ShouldBeNil)
	body, err = io.ReadAll(resp.Body)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, strings.Contains(string(body), "invalid json config contents"), test.ShouldBeTrue)
	err = resp.Body.Close()
	test.That(t, err, test.ShouldBeNil)

	// Test valid json
	client = &http.Client{}
	dummyCtx = t.Context()
	validConfig := "{\"cloud\":{\"app_address\":\"1\",\"id\":\"2\",\"secret\":\"3\"}}"
	urlParams = url.Values{
		"ssid":       {"notused"},
		"password":   {"notused"},
		"viamconfig": {validConfig},
	}
	req, err = http.NewRequestWithContext(dummyCtx, http.MethodPost, fmt.Sprintf("%s?%s", httpSaveURL, urlParams.Encode()), nil)
	test.That(t, err, test.ShouldBeNil)
	resp, err = client.Do(req)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, resp.StatusCode, test.ShouldEqual, 200)
	test.That(t, err, test.ShouldBeNil)
	body, err = io.ReadAll(resp.Body)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, strings.Contains(string(body), "Saving device config."), test.ShouldBeTrue)
	err = resp.Body.Close()
	test.That(t, err, test.ShouldBeNil)
	input := <-inputChan
	test.That(t, input.RawConfig, test.ShouldEqual, validConfig)
}

func writeTemplateFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	test.That(t, os.MkdirAll(dir, 0o755), test.ShouldBeNil)
	for name, contents := range files {
		test.That(t, os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600), test.ShouldBeNil)
	}
}

func renderPortal(t *testing.T, tmpl *template.Template) string {
	t.Helper()
	var sb strings.Builder
	test.That(t, tmpl.ExecuteTemplate(&sb, portalEntryTemplate, templateData{Manufacturer: "acme"}), test.ShouldBeNil)
	return sb.String()
}

func mockRunningLocally(t *testing.T, local bool) {
	t.Helper()
	old := utils.IsRunningLocally
	t.Cleanup(func() { utils.IsRunningLocally = old })
	utils.IsRunningLocally = local
}

func TestResolvePortalTemplates(t *testing.T) {
	validCustom := map[string]string{
		"base.html":  `<html>{{template "body" .}}</html>`,
		"index.html": `{{define "body"}}custom {{.Manufacturer}}{{end}}`,
	}
	validDev := map[string]string{"base.html": `dev {{.Manufacturer}}`}

	t.Run("custom dir problems fall back to built-in templates", func(t *testing.T) {
		mockRunningLocally(t, false)
		for _, tc := range []struct {
			name  string
			setup func(t *testing.T) string
		}{
			{name: "missing dir", setup: func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") }},
			{name: "not a directory", setup: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "file")
				test.That(t, os.WriteFile(path, []byte("x"), 0o600), test.ShouldBeNil)
				return path
			}},
			{name: "no html files", setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTemplateFiles(t, dir, map[string]string{"base.tmpl": "x"})
				return dir
			}},
			{name: "parse error", setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTemplateFiles(t, dir, map[string]string{"base.html": "{{ .Broken"})
				return dir
			}},
			{name: "missing base.html entrypoint", setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeTemplateFiles(t, dir, map[string]string{"index.html": validCustom["index.html"]})
				return dir
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				logger, logs := logging.NewObservedTestLogger(t)
				dir := tc.setup(t)
				n := &Subsystem{logger: logger, cfg: utils.NetworkConfiguration{PortalTemplatesDir: dir}}

				test.That(t, n.resolvePortalTemplates(), test.ShouldEqual, builtinTemplates)
				warnings := logs.FilterMessageSnippet("custom portal templates are unusable").All()
				test.That(t, len(warnings), test.ShouldEqual, 1)
				test.That(t, warnings[0].ContextMap()["dir"], test.ShouldEqual, dir)
			})
		}
	})

	t.Run("unset uses built-in templates", func(t *testing.T) {
		mockRunningLocally(t, false)
		n := &Subsystem{logger: logging.NewTestLogger(t)}
		test.That(t, n.resolvePortalTemplates(), test.ShouldEqual, builtinTemplates)
		test.That(t, renderPortal(t, builtinTemplates), test.ShouldContainSubstring, "acme")
	})

	t.Run("valid custom dir is used", func(t *testing.T) {
		mockRunningLocally(t, false)
		dir := t.TempDir()
		writeTemplateFiles(t, dir, validCustom)
		n := &Subsystem{logger: logging.NewTestLogger(t), cfg: utils.NetworkConfiguration{PortalTemplatesDir: dir}}
		test.That(t, renderPortal(t, n.resolvePortalTemplates()), test.ShouldEqual, "<html>custom acme</html>")
	})

	t.Run("dev override is ignored when not running locally", func(t *testing.T) {
		mockRunningLocally(t, false)
		utils.MockViamDirs(t)
		writeTemplateFiles(t, filepath.Join(utils.ViamDirs.Tmp, "templates"), validDev)
		n := &Subsystem{logger: logging.NewTestLogger(t)}
		test.That(t, n.resolvePortalTemplates(), test.ShouldEqual, builtinTemplates)
	})

	t.Run("running locally", func(t *testing.T) {
		mockRunningLocally(t, true)
		utils.MockViamDirs(t)
		writeTemplateFiles(t, filepath.Join(utils.ViamDirs.Tmp, "templates"), validDev)

		t.Run("dev override is used", func(t *testing.T) {
			n := &Subsystem{logger: logging.NewTestLogger(t)}
			test.That(t, renderPortal(t, n.resolvePortalTemplates()), test.ShouldEqual, "dev acme")
		})
		t.Run("custom dir takes precedence over dev override", func(t *testing.T) {
			dir := t.TempDir()
			writeTemplateFiles(t, dir, validCustom)
			n := &Subsystem{logger: logging.NewTestLogger(t), cfg: utils.NetworkConfiguration{PortalTemplatesDir: dir}}
			test.That(t, renderPortal(t, n.resolvePortalTemplates()), test.ShouldEqual, "<html>custom acme</html>")
		})
		t.Run("unusable custom dir falls back to dev override", func(t *testing.T) {
			n := &Subsystem{
				logger: logging.NewTestLogger(t),
				cfg:    utils.NetworkConfiguration{PortalTemplatesDir: filepath.Join(t.TempDir(), "nope")},
			}
			test.That(t, renderPortal(t, n.resolvePortalTemplates()), test.ShouldEqual, "dev acme")
		})
	})
}

func TestCurrentPortalTemplates(t *testing.T) {
	t.Run("not running locally, templates are not re-read after the portal starts", func(t *testing.T) {
		mockRunningLocally(t, false)
		dir := t.TempDir()
		writeTemplateFiles(t, dir, map[string]string{"base.html": "v1 {{.Manufacturer}}"})
		n := &Subsystem{logger: logging.NewTestLogger(t), cfg: utils.NetworkConfiguration{PortalTemplatesDir: dir}}

		test.That(t, n.currentPortalTemplates(), test.ShouldEqual, builtinTemplates)

		n.portalTemplates = n.resolvePortalTemplates()
		writeTemplateFiles(t, dir, map[string]string{"base.html": "v2 {{.Manufacturer}}"})
		test.That(t, renderPortal(t, n.currentPortalTemplates()), test.ShouldEqual, "v1 acme")
	})

	t.Run("running locally, templates are re-read on every call", func(t *testing.T) {
		mockRunningLocally(t, true)
		utils.MockViamDirs(t)
		dir := t.TempDir()
		writeTemplateFiles(t, dir, map[string]string{"base.html": "v1 {{.Manufacturer}}"})
		n := &Subsystem{logger: logging.NewTestLogger(t), cfg: utils.NetworkConfiguration{PortalTemplatesDir: dir}}

		n.portalTemplates = n.resolvePortalTemplates()
		writeTemplateFiles(t, dir, map[string]string{"base.html": "v2 {{.Manufacturer}}"})
		test.That(t, renderPortal(t, n.currentPortalTemplates()), test.ShouldEqual, "v2 acme")
	})
}

func TestWebPortalServesCustomTemplates(t *testing.T) {
	mockRunningLocally(t, false)
	dir := t.TempDir()
	writeTemplateFiles(t, dir, map[string]string{"base.html": "branded {{.Manufacturer}}"})

	logger := logging.NewTestLogger(t)
	n := Subsystem{
		cfg:        utils.NetworkConfiguration{Manufacturer: "acme", PortalTemplatesDir: dir},
		portalData: &userInputData{input: &userInput{}, inputChan: make(chan userInput, 1), connState: NewConnectionState(logger)},
		logger:     logger,
		connState:  NewConnectionState(logger),
		netState:   &networkState{},
		banner:     &banner{},
		errors:     &errorList{},
	}
	test.That(t, n.startWeb("localhost", 8082), test.ShouldBeNil)
	defer func() { test.That(t, n.webServer.Close(), test.ShouldBeNil) }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8082/", nil)
	test.That(t, err, test.ShouldBeNil)
	resp, err := http.DefaultClient.Do(req)
	test.That(t, err, test.ShouldBeNil)
	defer func() { test.That(t, resp.Body.Close(), test.ShouldBeNil) }()
	body, err := io.ReadAll(resp.Body)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, resp.StatusCode, test.ShouldEqual, http.StatusOK)
	test.That(t, string(body), test.ShouldEqual, "branded acme")
}
