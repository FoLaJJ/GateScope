package task

import (
	"context"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

type Scheduler struct {
	cron    *cron.Cron
	manager *Manager
	store   store.Store
}

func NewScheduler(manager *Manager, s store.Store) *Scheduler {
	return &Scheduler{
		cron:    cron.New(),
		manager: manager,
		store:   s,
	}
}

func (s *Scheduler) Start() error {
	ctx := context.Background()
	tt := models.TaskTypeScheduled
	tasks, _, err := s.store.ListTasks(ctx, store.TaskFilter{
		Type:  &tt,
		Limit: 100,
	})
	if err != nil {
		return err
	}

	log := logger.Named("scheduler")
	for _, task := range tasks {
		if task.CronExpr == "" {
			continue
		}
		taskID := task.ID
		cronExpr := task.CronExpr
		_, err := s.cron.AddFunc(cronExpr, func() {
			t, err := s.store.GetTask(ctx, taskID)
			if err != nil {
				log.Error("scheduled task lookup failed", zap.String("task_id", taskID), zap.Error(err))
				return
			}
			if t.Status == models.TaskStatusRunning {
				return
			}
			t.Status = models.TaskStatusPending
			_ = s.store.UpdateTask(ctx, t)
			if err := s.manager.Start(context.Background(), taskID); err != nil {
				log.Error("scheduled task failed to start", zap.String("task_id", taskID), zap.Error(err))
			}
		})
		if err != nil {
			log.Error("invalid cron expr", zap.String("task_id", taskID), zap.Error(err))
		}
	}

	s.cron.Start()
	return nil
}

func (s *Scheduler) Stop() {
	s.cron.Stop()
}

func (s *Scheduler) AddTask(taskID string, cronExpr string) error {
	_, err := s.cron.AddFunc(cronExpr, func() {
		if err := s.manager.Start(context.Background(), taskID); err != nil {
			logger.Named("scheduler").Error("scheduled task failed", zap.String("task_id", taskID), zap.Error(err))
		}
	})
	return err
}
