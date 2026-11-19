# Custom provisioning portal templates

During wifi provisioning, viam-agent serves a setup page from its hotspot at `http://10.42.0.1`
(any `*.setup` hostname resolves to it). Device makers can replace that page with their own branded
templates. This document is the contract between those templates and the agent.

**Current template contract version: 1**

## Configuration

Point `network_configuration.portal_templates_dir` at an absolute path, normally in
`/etc/viam-defaults.json` so it applies on first boot, before the device has ever reached the cloud:

```json
{
  "network_configuration": {
    "manufacturer": "Acme",
    "model": "Rover 2",
    "portal_templates_dir": "/etc/viam/portal"
  }
}
```

Templates are loaded when provisioning starts and kept for that provisioning session. Changes on
disk take effect the next time provisioning starts. When viam-agent runs in local (development)
mode, i.e. its binary is outside `/opt/viam`, templates are re-read on every page load instead, so
edits show up on refresh.

## Directory layout

```
/etc/viam/portal/
├── manifest.json   required: {"template_api_version": 1}
├── base.html       required: the page entrypoint
└── *.html          optional: more templates, available to base.html via {{template "name" .}}
```

- Every `*.html` file directly in the directory is parsed as one Go
  [`html/template`](https://pkg.go.dev/html/template) set; each file defines a template named after
  the file, and files can declare more with `{{define "name"}}`. Subdirectories and other files are
  ignored.
- `base.html` is executed to render every page.
- The custom set fully replaces the built-in templates; nothing is inherited from them.
- Only HTML is served: no static files, and the hotspot has no internet. Inline all CSS
  (`<style>`), JavaScript (`<script>`), fonts, and images (`data:` URIs or inline SVG).
- Only Go's built-in template functions are available (`eq`, `len`, `and`, `not`, `printf`, ...).
  Output is escaped automatically for its HTML context.

## Security requirements

The page collects wifi passwords and machine secrets, so only root may be able to change it:

- The directory, `manifest.json`, and every template must be owned by root and not writable by
  group or others (e.g. directory `0755`, files `0644`, owner `root:root`).
- Every parent directory up to `/` must be owned by root and not writable by others, except for
  directories with the sticky bit set (like `/tmp`).
- No symlinks: not in the configured path, and not as templates or manifest.

## Data available to templates

| Field | Type | Meaning |
|---|---|---|
| `.Manufacturer` | string | `network_configuration.manufacturer` (default `viam`) |
| `.Model` | string | `network_configuration.model` (default `custom`) |
| `.FragmentID` | string | `network_configuration.fragment_id`, may be empty |
| `.Banner` | string | Status message to show, e.g. `Added credentials for SSID: home`; may be empty |
| `.Errors` | []string | Errors to show, from the last submission or connection attempt |
| `.VisibleSSIDs` | []NetworkInfo | Networks found by the last scan, strongest first; may be empty |
| `.LastNetwork` | NetworkInfo | The wifi network the device last tried |
| `.IsOnline` | bool | The device is connected; wifi credentials are not needed |
| `.IsConfigured` | bool | The device has its machine config; `viamconfig` is not needed |

`NetworkInfo`:

| Field | Type | Meaning |
|---|---|---|
| `.SSID` | string | Network name |
| `.Security` | string | Space-separated security flags, e.g. `WPA2 WPA3`; `-` for open networks |
| `.Signal` | int32 | Signal strength, 0-100 |
| `.Connected` | bool | The device is currently connected to it |
| `.LastError` | string | Last error connecting to it, may be empty |
| `.Type` | string | Network type: `wifi`, `wired`, or `hotspot` |

`.Banner` and `.Errors` are cleared after every render, so each message is shown once.

## Form submission

The page must submit an HTML form with `method="post"` to `/save`, using these field names:

| Field | Required when | Contents |
|---|---|---|
| `ssid` | `.IsOnline` is false | Wifi network name |
| `password` | never | Wifi password (empty for open networks) |
| `viamconfig` | `.IsConfigured` is false | The machine's `viam.json`; must be JSON with a `cloud` object containing `id`, `app_address`, and `secret` or a complete `api_key` |

The agent always answers with `303 See Other` redirecting to `/`. Problems with the submission are
shown through `.Errors`, and progress through `.Banner`, on that next render. Any other path renders
the same page as `/`.

## Failure behavior

The built-in Viam page is used, and a warning naming the reason is logged, when:

- the directory is missing or not a directory, or a security requirement is not met;
- `manifest.json` is missing, invalid, or declares a different contract version than the agent;
- there is no `base.html`, or a template fails to parse;
- rendering fails, e.g. a template uses a field that doesn't exist. This is decided per page load,
  since it can depend on the data (such as a non-empty `.Errors`).

## Compatibility policy

- **Compatible changes** keep the version: adding a data field, adding an optional form field,
  adding documentation.
- **Breaking changes** bump the version: removing or renaming a data or form field, changing a
  field's type or meaning, changing the entrypoint, or changing how `/save` behaves.

The agent updates itself independently of a device's OS image. After a breaking change, devices
whose templates declare the old version show the built-in page, rather than a broken one, until the
templates are updated to the new version.

## Changelog

- **1**: Initial contract.
