package networking

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	errw "github.com/pkg/errors"
)

// The portal page collects wifi passwords and machine secrets, so custom templates are trusted
// code: anyone who can change them can phish or exfiltrate those secrets. Templates from
// portal_templates_dir are therefore only used if nothing but root can modify them.

// portalTemplateManifest is the file in portal_templates_dir that declares which version of the
// template contract (portalTemplateAPIVersion) the templates were written for.
const portalTemplateManifest = "manifest.json"

type templateManifest struct {
	TemplateAPIVersion int `json:"template_api_version"`
}

// loadCustomTemplates loads the templates in portal_templates_dir: only root may be able to modify
// them (see rootOwnedTemplatePaths), and their manifest must declare the template contract version
// this agent implements.
func loadCustomTemplates(dir string) (*template.Template, error) {
	t, err := parseTemplateDir(dir, true)
	if err != nil {
		return nil, err
	}
	if err := checkTemplateManifest(dir); err != nil {
		return nil, err
	}
	return t, nil
}

func checkTemplateManifest(dir string) error {
	path := filepath.Join(dir, portalTemplateManifest)
	if err := checkRootControlledFile(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errw.Errorf("%s is missing; it must declare the template contract version, e.g. {\"template_api_version\": %d}",
				path, portalTemplateAPIVersion)
		}
		return err
	}
	//nolint:gosec // path was just checked to be a root-controlled regular file
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m templateManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return errw.Wrapf(err, "parsing %s", path)
	}
	if m.TemplateAPIVersion == 0 {
		return errw.Errorf("%s does not set template_api_version", path)
	}
	if m.TemplateAPIVersion != portalTemplateAPIVersion {
		return errw.Errorf("%s targets template contract version %d, but this agent implements version %d",
			path, m.TemplateAPIVersion, portalTemplateAPIVersion)
	}
	return nil
}

// portalTemplatesOwnerUID is the owner custom templates must have. It is root in production;
// tests replace it because they cannot create root-owned files.
var portalTemplatesOwnerUID uint32

// templatePaths lists every *.html file directly inside dir, without ownership checks.
func templatePaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".html" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}

// rootOwnedTemplatePaths lists every *.html file directly inside dir, requiring that only root can
// modify them:
//   - dir and every template must be owned by root and not writable by group or others;
//   - every parent of dir must be too, or dir could be renamed and replaced. Parents with the sticky
//     bit (like /tmp) may be world-writable, since others cannot rename entries they don't own;
//   - no symlinks, in the path of dir or among the templates.
func rootOwnedTemplatePaths(dir string) ([]string, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	if resolved != dir {
		return nil, errw.Errorf("%s is a symlink or has one in its path (resolves to %s); configure the real path", dir, resolved)
	}

	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		if err := checkRootControlled(parent, true); err != nil {
			return nil, errw.Wrap(err, "unsafe parent directory")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	if err := checkRootControlled(dir, false); err != nil {
		return nil, err
	}

	paths, err := templatePaths(dir)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if err := checkRootControlledFile(path); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

// checkRootControlledFile returns an error unless path is a regular file (not a symlink) that only
// root can modify.
func checkRootControlledFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return errw.Errorf("%s is a symlink, which is not allowed for portal templates", path)
	}
	if !info.Mode().IsRegular() {
		return errw.Errorf("%s is not a regular file", path)
	}
	return checkRootControlled(path, false)
}

// checkRootControlled returns an error unless only root can modify path. Root itself is always
// accepted as an owner, so system directories like / and /etc pass in tests too.
func checkRootControlled(path string, allowSticky bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errw.Errorf("cannot determine the owner of %s", path)
	}
	if st.Uid != 0 && st.Uid != portalTemplatesOwnerUID {
		return errw.Errorf("%s is owned by uid %d, but must be owned by root", path, st.Uid)
	}
	perm := info.Mode().Perm()
	if perm&0o022 != 0 && !(allowSticky && info.Mode()&fs.ModeSticky != 0) {
		return errw.Errorf("%s is writable by group or others (mode %#o), but must only be writable by its owner", path, perm)
	}
	return nil
}
