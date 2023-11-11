package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

var (
	activeBackgroundWorkers sync.WaitGroup
)

func SubsystemUpdates(ctx context.Context, logger *zap.SugaredLogger, cfg map[string]*pb.DeviceSubsystemConfig) {
	subsystemsMu.Lock()
	defer subsystemsMu.Unlock()
	// stop/remove orphaned subsystems
	for key, sub := range loadedSubsystems {
		if _, ok := cfg[key]; !ok {
			if err := sub.Stop(ctx); err != nil {
				logger.Error(err)
				continue
			}
			delete(loadedSubsystems, key)
		}
	}

	// add new subsystems
	for name, subCfg := range cfg {
		if _, ok := loadedSubsystems[name]; !ok {
			creator := registry.GetCreator(name)
			if creator != nil {
				sub, err := creator(ctx, logger, subCfg)
				if err != nil {
					logger.Error(err)
					continue
				}
				loadedSubsystems[name] = sub
			}
			logger.Warnw("unknown subsystem", "name", name)
		}
	}

	// check updates and (re)start
	for name, sub := range loadedSubsystems {
		cancelCtx, cancel := context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
		restart, err := sub.Update(cancelCtx, cfg[name])
		if err != nil {
			logger.Error(err)
			continue
		}
		if restart {
			if err := sub.Stop(ctx); err != nil {
				logger.Error(err)
				continue
			}
		}
		if err := sub.Start(ctx); err != nil {
			logger.Error(err)
			continue
		}
	}
}

func CheckUpdates(ctx context.Context, logger *zap.SugaredLogger) time.Duration {
	logger.Info("SMURF check for update")
	cfg, interval, err := GetConfig(ctx)
	if err != nil {
		logger.Error(err)
	}

	fmt.Println("SMURF CONFIG", cfg)

	// update and (re)start subsystems
	SubsystemUpdates(ctx, logger, cfg)

	// randomly fuzz the interval by +/- 5%
	return fuzzTime(interval, 0.05)
}

func SubsystemHealthChecks(ctx context.Context, logger *zap.SugaredLogger) {
	logger.Info("SMURF check statuses")
	subsystemsMu.Lock()
	defer subsystemsMu.Unlock()
	for _, sub := range loadedSubsystems {
		ctxTimeout, cancelFunc := context.WithTimeout(ctx, time.Second*15)
		if err := sub.HealthCheck(ctxTimeout); err != nil {
			logger.Error("subsystem healthcheck failed")
			if err := sub.Stop(ctx); err != nil {
				logger.Error(errors.Wrap(err, "stopping subsystem"))
			}
			if err := sub.Start(ctx); err != nil {
				logger.Error(errors.Wrap(err, "restarting subsystem"))
			}
		}
		cancelFunc()
	}
}

func CloseAll(ctx context.Context, logger *zap.SugaredLogger) {
	// close all subsystems
	for _, sub := range loadedSubsystems {
		if err := sub.Stop(ctx); err != nil {
			logger.Error(err)
		}
	}
	activeBackgroundWorkers.Wait()
}

func StartBackgroundChecks(ctx context.Context, logger *zap.SugaredLogger) {
	activeBackgroundWorkers.Add(1)
	go func() {
		checkInterval := CheckUpdates(ctx, logger)
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()
		defer activeBackgroundWorkers.Done()
		for {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			// case <-sigHUP:
			// 	checkUpdates(ctx)
			case <-timer.C:
				checkInterval = CheckUpdates(ctx, logger)
				timer.Reset(checkInterval)
				SubsystemHealthChecks(ctx, logger)
			}
		}
	}()
}
