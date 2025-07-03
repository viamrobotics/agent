package networking

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestWebPortalJsonParse(t *testing.T) {
	bindAddr := "localhost"
	bindPort := 8080
	httpSaveURL := fmt.Sprintf("http://%s/save", net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)))

	inputChan := make(chan userInput, 1)
	n := Networking{
		portalData: &userInputData{input: &userInput{}, inputChan: inputChan, connState: &connectionState{}},
		logger:     logging.NewTestLogger(t),
		connState:  &connectionState{},
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
	dummyCtx := context.Background()
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
	dummyCtx = context.Background()
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
	dummyCtx = context.Background()
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
