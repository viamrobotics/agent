package agent

import (
	"context"
)

func (is *InternalSubsystem) HealthCheck(ctx context.Context) (errRet error) {
	// todo: flesh this out. SIGUSR1 isn't available on windows.
	return nil
}
