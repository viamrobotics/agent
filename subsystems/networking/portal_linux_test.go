package networking

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestWebPortalJsonParse(t *testing.T) {
	bindAddr := "localhost"
	bindPort := 8080
	httpSaveUrl := fmt.Sprintf("http://%s:%d/save", bindAddr, bindPort)

	n := Networking{portalData: &userInputData{input: &userInput{}},
		logger:    logging.NewTestLogger(t),
		connState: &connectionState{},
		netState:  &networkState{},
		banner:    &banner{},
		errors:    &errorList{}}
	err := n.startWeb(bindAddr, bindPort)
	defer func() {
		err = n.webServer.Close()
		test.That(t, err, test.ShouldBeNil)
	}()
	test.That(t, err, test.ShouldBeNil)

	// Test json missing cloud section
	resp, err := http.PostForm(httpSaveUrl, url.Values{"ssid": {"notused"}, "password": {"notused"}, "viamconfig": {"{}"}})
	test.That(t, resp.StatusCode, test.ShouldEqual, 200)
	test.That(t, err, test.ShouldBeNil)
	body, err := io.ReadAll(resp.Body)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, strings.Contains(string(body), "incomplete cloud config provided"), test.ShouldBeTrue)

	// Test malformed json
	resp, err = http.PostForm(httpSaveUrl, url.Values{"ssid": {"notused"}, "password": {"notused"}, "viamconfig": {"{{{"}})
	test.That(t, resp.StatusCode, test.ShouldEqual, 200)
	test.That(t, err, test.ShouldBeNil)
	body, err = io.ReadAll(resp.Body)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, strings.Contains(string(body), "invalid json config contents"), test.ShouldBeTrue)

	// TODO: test handling valid json
}
