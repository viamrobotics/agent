#!/bin/sh
# agent-exit-probe.sh is invoked by viam-agent.service as an ExecStopPost= command.
# It is OBSERVABILITY ONLY: it never starts, stops, or restarts anything and never
# affects the viam-agent service. Its sole job is to log, on every exit of the
# service, whether viam-agent would have been thrown into "detached mode" (running
# viam-server alone) under the proposed bad-binary safeguard -- WITHOUT actually
# doing so. That lets us measure, in the wild, how often a "would-detach" exit
# really happens and why, before we trust it to launch viam-server-detached.
#
# systemd runs ExecStopPost= after the service stops, INCLUDING when the service
# exited unexpectedly or never managed to start (e.g. an unrunnable "bad" binary --
# the case from the Feb file-permissions postmortem that motivates this work). It
# passes the same exit information systemd itself uses to decide success vs failure:
#
#   $SERVICE_RESULT  the overall verdict, e.g. success, exit-code, signal, timeout,
#                    core-dump, watchdog, oom-kill, start-limit-hit, resources
#   $EXIT_CODE       how the main process ended: exited | killed | dumped
#   $EXIT_STATUS     numeric exit code (when exited) or signal name (when killed/dumped)
#
# We classify the verdict primarily from $SERVICE_RESULT, which is systemd's own
# overall judgement of the exit. This is what lets us distinguish a clean stop from
# an OOM kill or a timeout: all three end the process with SIGKILL/SIGTERM, so the
# raw signal alone ($EXIT_STATUS) is ambiguous, but $SERVICE_RESULT is not (oom-kill
# and timeout are their own results). $SERVICE_RESULT is well defined here because
# this unit does not set SuccessExitStatus=; it follows systemd's documented
# defaults, under which exit 0 and the signals SIGHUP/SIGINT/SIGTERM/SIGPIPE are
# already "success". We still log $EXIT_CODE/$EXIT_STATUS raw for context.
#
# "Clean" (would NOT detach) mirrors the proposed detached-mode design's definition:
#   - $SERVICE_RESULT=success: a clean exit (status 0, e.g. a self-update) or a
#     stop signal (systemctl stop, or the process exiting on SIGTERM/INT/HUP/PIPE)
#   - $SERVICE_RESULT=signal with $EXIT_STATUS=KILL: a stray `kill -9`, which the
#     design whitelists so it does not look "bad"
# Everything else is a "would-detach" exit, covering all five cases the design would
# act on: non-zero exit ($SERVICE_RESULT=exit-code, the Feb postmortem), crash
# signals like SIGSEGV/SIGABRT (signal), timeout, watchdog, and OOM kill (oom-kill).
#
# The "viam-agent exit probe:" marker below is what the app side keys a metric off
# of (counting verdict=would-detach, labeled by part ID). Keep this script trivial
# and fast: it runs as root inside the service stop timeout, and the leading "-" on
# the ExecStopPost= line means a failure here can never affect the service.

set -u

case "${SERVICE_RESULT:-}" in
success)
	verdict=clean
	;;
signal)
	# A bare `kill -9` reports result=signal/status=KILL here (this unit does not
	# whitelist SIGKILL via SuccessExitStatus=). The design treats that as not-bad;
	# every other signal (SIGSEGV, SIGABRT, ...) is a crash and would detach.
	case "${EXIT_STATUS:-}" in
	KILL) verdict=clean ;;
	*) verdict=would-detach ;;
	esac
	;;
*)
	# exit-code, timeout, watchdog, oom-kill, core-dump, start-limit-hit, protocol,
	# resources, or an empty/unrecognized result -- all treated as would-detach.
	verdict=would-detach
	;;
esac

# Single-line, greppable. stdout from ExecStopPost= is captured by the journal under
# the viam-agent.service unit.
echo "viam-agent exit probe: verdict=${verdict} service_result=${SERVICE_RESULT:-} exit_code=${EXIT_CODE:-} exit_status=${EXIT_STATUS:-}"
