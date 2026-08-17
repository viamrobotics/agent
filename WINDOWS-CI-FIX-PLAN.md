# Windows CI: skipped tests and how to fix them

The `test-windows` job in `.github/workflows/workflow.yaml` runs `go test ./...` over
every package, with a `WINDOWS_SKIP` list of `go test -skip` patterns for the tests
that do not pass on Windows yet. This document records why each entry is there.

Two conventions about that list:

- Exclusions are **per-test, not per-package**, so a package with one broken test
  still contributes the rest of its coverage. Each entry is a `-skip` pattern:
  `/`-separated elements match successive subtest names, and the whole list is
  joined with `|` into one alternation.
- Everything in the list is a **known failure, not a flake**. None of it has been
  investigated beyond reproducing the failure; the list exists so Windows can start
  gating PRs at all. Deleting entries as the underlying problems get fixed is the
  point, and nothing should be added without a reason recorded here.

Not `make test` for this job: that target passes `-race`, which needs cgo, which
needs a C toolchain we don't otherwise depend on for Windows builds.

## Skipped tests

### `^TestUpdateBinary$` — `version_control_test.go:127`

Fails with `GetFileAttributesEx ...\cache\source-binary-0.70.0: The system cannot
find the file specified`. Three leaf subtests fail, but the later subtests reuse the
state the failing ones set up, so the whole test is skipped rather than the three
leaves. This is also one of the two callers of `utils.BuildViamAgent` (see
`TestIsValidAgentBinary` below).

### `^TestForceSymlink$` — `utils/utils_test.go:81`

### `^TestInstall$/^(fresh_install|self_update)$` — `agent_test.go:19`

Both come down to `ForceSymlink`, which fails on Windows with `is a directory` or
`The system cannot find the file specified`. Fixing the symlink helper should clear
both entries; the `TestInstall` subtests not listed here already pass.

### `^TestDecompressFile$` — `utils/utils_test.go:28`

Renaming the decompressed file out of `tmp/` fails with `The process cannot access
the file because it is being used by another process` — a handle on the decompressed
file is still open at rename time. Windows does not allow renaming an open file the
way Unix does, so the fix is to close the destination before the rename.

### `^TestConvertJson$` — `utils/config_test.go:18`

The test compares a fixture that sets `viam_server_start_timeout_minutes: 10`
against `DefaultConfig()`. That default is 10 minutes on Linux but 1 minute on
Windows, so the comparison fails purely on the platform-dependent default. Fix by
making the expectation platform-aware (or by having the fixture set a value that is
not the Linux default).

### `^TestSystemdManagerInstallService$/^(new_install_in_default_directory|new_install_in_fallback_directory|identical_install_in_fallback_directory|outdated_install_in_fallback_directory)$` — `utils/systemd/manager_test.go:35`

Writes into a fallback service directory fail with `The system cannot find the path
specified`. The default-directory subtests that are not in this list pass.

### `^TestDownloadFile$/^(does_not_overwrite_existing_files|handles_multiple_duplicates|handles_files_with_special_characters_in_name)$` — `utils/utils_test.go:171`

### `^TestInitPaths$/^(failure_cannot_create_directory|failure_not_directory)$` — `utils/utils_test.go:506`

These subtests either assert on an error that Windows does not produce (the
`failure_*` cases lean on Unix permission and file-type semantics), or leave a file
handle open that blocks `t.TempDir` cleanup at the end of the test.

### `^TestIsValidAgentBinary$` — `utils/utils_test.go:594`

`utils.BuildViamAgent` (`utils/testutils.go:88`) shells out to `make test-build`
with `TESTBUILD_OUTPUT_PATH` set to a backslashed Windows temp path. The backslashes
are eaten before `go build -o` sees them, so the binary lands in the repo root under
a mangled name and the path the helper returns does not exist.

Only the `valid_file` subtest asserts on that path, but the `BuildViamAgent` call
sits in the table literal rather than inside the subtest, so skipping the leaf alone
would still build the agent — and would fail the parent outright on a runner without
`make`. Skipping the parent also keeps the mangled file out of the checkout.

Fixing `BuildViamAgent` to pass a path `go build -o` accepts on Windows (forward
slashes, or quoting that survives the `make` invocation) would unblock this test and
likely help `TestUpdateBinary`, the helper's only other caller.

### `^TestFetchRestartStatus$` — `subsystems/viamserver/restart_status_test.go:22`

Fails with `listen tcp 127.0.0.1:8080: bind: An attempt was made to access a socket
in a way forbidden by its access permissions`. Port 8080 falls inside a Windows
excluded port range (reserved by Hyper-V / WinNAT), so the bind is refused even
though nothing is listening. Fix by binding port 0 and reading back the assigned
port instead of hardcoding 8080.
