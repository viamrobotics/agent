module github.com/viamrobotics/agent

go 1.25.1

// This must be a replace because a bunch of our deps also use it + `go mod tidy` fails from the conflict
// if you switch it out in the require block.
// We fork this bc the stock version doubles agent binary from 25mb -> 50mb.
replace github.com/hashicorp/go-getter => github.com/viam-labs/go-getter v0.0.0-20251022162721-98d73b852c8a

require (
	github.com/Masterminds/semver/v3 v3.3.1
	github.com/cucumber/godog v0.15.1
	github.com/gabriel-vasile/mimetype v1.4.9
	github.com/godbus/dbus/v5 v5.1.1-0.20241109141230-b9236d654833
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-getter v1.8.3
	github.com/jessevdk/go-flags v1.6.1
	github.com/nightlyone/lockfile v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/samber/lo v1.52.0
	github.com/samber/mo v1.16.0
	github.com/schollz/progressbar/v3 v3.18.0
	github.com/sergeymakinen/go-systemdconf/v2 v2.0.2
	github.com/tidwall/jsonc v0.3.2
	github.com/ulikunitz/xz v0.5.15
	github.com/viamrobotics/gonetworkmanager/v2 v2.2.3
	go.bug.st/serial v1.6.4
	go.uber.org/zap v1.27.0
	go.viam.com/api v0.1.508
	go.viam.com/rdk v0.109.0
	go.viam.com/test v1.2.4
	go.viam.com/utils v0.4.3
	golang.org/x/sys v0.38.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.10
	tinygo.org/x/bluetooth v0.11.0
)

require (
	cloud.google.com/go v0.121.2 // indirect
	cloud.google.com/go/storage v1.53.0 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/creack/goselect v0.1.2 // indirect
	github.com/cucumber/gherkin/go/v26 v26.2.0 // indirect
	github.com/cucumber/messages/go/v21 v21.0.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/desertbit/timer v0.0.0-20180107155436-c41aec40b27f // indirect
	github.com/dgottlieb/smarty-assertions v1.2.6 // indirect
	github.com/edaniels/golog v0.0.0-20250821172758-0d08e67686a9 // indirect
	github.com/go-jose/go-jose/v4 v4.1.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/gofrs/uuid v4.3.1+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.2 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.4 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/improbable-eng/grpc-web v0.15.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx v1.2.29 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/miekg/dns v1.1.56 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/interceptor v0.1.42 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns v0.0.12 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.8.26 // indirect
	github.com/pion/sctp v1.8.41 // indirect
	github.com/pion/sdp/v3 v3.0.16 // indirect
	github.com/pion/srtp/v2 v2.0.20 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.10 // indirect
	github.com/pion/transport/v3 v3.1.1 // indirect
	github.com/pion/turn/v2 v2.1.6 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/saltosystems/winrt-go v0.0.0-20240509164145-4f7860a3bd2b // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/soypat/cyw43439 v0.0.0-20241116210509-ae1ce0e084c5 // indirect
	github.com/soypat/seqs v0.0.0-20240527012110-1201bab640ef // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/srikrsna/protoc-gen-gotag v0.6.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/tinygo-org/cbgo v0.0.4 // indirect
	github.com/tinygo-org/pio v0.0.0-20231216154340-cd888eb58899 // indirect
	github.com/viamrobotics/ice/v2 v2.3.40 // indirect
	github.com/viamrobotics/webrtc/v3 v3.99.16 // indirect
	github.com/viamrobotics/zeroconf v1.0.13 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/zitadel/oidc/v3 v3.37.0 // indirect
	github.com/zitadel/schema v1.3.1 // indirect
	go.mongodb.org/mongo-driver v1.17.1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/exp v0.0.0-20251113190631-e25ba8c21ef6 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/term v0.37.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
	gonum.org/v1/gonum v0.16.0 // indirect
	google.golang.org/api v0.246.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250825161204-c5933d9347a5 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	nhooyr.io/websocket v1.8.9 // indirect
)
