package api

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/AutoScan/agentscan/internal/auth"
	"github.com/AutoScan/agentscan/internal/core/config"
	"github.com/AutoScan/agentscan/internal/core/eventbus"
	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/AutoScan/agentscan/internal/geoip"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/AutoScan/agentscan/internal/task"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Server struct {
	cfg        *config.Config
	store      store.Store
	bus        eventbus.EventBus
	auth       *auth.Service
	taskMgr    *task.Manager
	scheduler  *task.Scheduler
	geoSvc     *geoip.Service
	wsHub      *WSHub
	router     *gin.Engine
	httpSrv    *http.Server
	frontendFS fs.FS
	instanceID string
}

// NewServer creates a new API server. Pass a non-nil frontendFS (from go:embed)
// to serve the SPA from the embedded filesystem; pass nil to skip.
func NewServer(cfg *config.Config, s store.Store, bus eventbus.EventBus, frontendFS fs.FS) *Server {
	authSvc := auth.NewService(s, cfg.Auth)
	taskMgr := task.NewManager(s, bus, cfg)
	scheduler := task.NewScheduler(taskMgr, s)
	geoSvc := geoip.NewService(cfg.GeoIP.DatabasePath)

	srv := &Server{
		cfg:        cfg,
		store:      s,
		bus:        bus,
		auth:       authSvc,
		taskMgr:    taskMgr,
		scheduler:  scheduler,
		geoSvc:     geoSvc,
		wsHub:      NewWSHub(),
		frontendFS: frontendFS,
		instanceID: uuid.NewString(),
	}

	srv.setupRouter()
	return srv
}

func (s *Server) setupRouter() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(instanceIDMiddleware(s.instanceID))
	r.Use(accessLogMiddleware())
	r.Use(corsMiddleware())

	api := r.Group("/api/v1")
	{
		api.POST("/auth/login", s.handleLogin)

		protected := api.Group("")
		protected.Use(s.authMiddleware())
		{
			protected.GET("/auth/me", s.handleMe)

			protected.GET("/tasks", s.handleListTasks)
			protected.POST("/tasks", s.handleCreateTask)
			protected.GET("/tasks/:id", s.handleGetTask)
			protected.GET("/tasks/:id/targets", s.handleGetTaskTargets)
			protected.GET("/tasks/:id/events", s.handleListTaskEvents)
			protected.DELETE("/tasks/:id", s.handleDeleteTask)
			protected.POST("/tasks/:id/start", s.handleStartTask)
			protected.POST("/tasks/:id/stop", s.handleStopTask)

			protected.GET("/assets", s.handleListAssets)
			protected.GET("/assets/:id", s.handleGetAsset)
			protected.GET("/assets/:id/vulns", s.handleGetAssetVulns)

			protected.GET("/vulns", s.handleListVulns)
			protected.GET("/vulns/:id", s.handleGetVuln)
			protected.GET("/rules/catalog", s.handleRuleCatalog)

			protected.GET("/dashboard/stats", s.handleDashboardStats)

			protected.GET("/reports/:taskId/excel", s.handleExportExcel)

			protected.GET("/dashboard/trends", s.handleDashboardTrends)

			protected.POST("/import/targets", s.handleImportTargets)
		}
	}

	r.GET("/api/v1/ws", s.handleWebSocket)

	r.NoRoute(s.serveFrontend())

	s.router = r
}

func (s *Server) Start() error {
	log := logger.Named("api")

	ctx := context.Background()
	if err := s.auth.EnsureAdminUser(ctx); err != nil {
		log.Warn("ensure admin user", zap.Error(err))
	}
	if recovered, err := s.taskMgr.RecoverInterruptedTasks(ctx); err != nil {
		log.Warn("recover interrupted tasks", zap.Error(err))
	} else if recovered > 0 {
		log.Warn("recovered interrupted tasks", zap.Int("count", recovered))
	}
	if updated, err := s.taskMgr.RecalculateAssetRisks(ctx); err != nil {
		log.Warn("recalculate asset risks", zap.Error(err))
	} else if updated > 0 {
		log.Info("recalculated asset risks", zap.Int("count", updated))
	}

	s.registerWSHandlers()

	if err := s.scheduler.Start(); err != nil {
		log.Warn("scheduler start", zap.Error(err))
	}

	go s.wsHub.Run()

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port),
		Handler: s.router,
	}

	log.Info("server listening", zap.String("addr", s.httpSrv.Addr))
	return s.httpSrv.ListenAndServe()
}

// Shutdown performs a graceful shutdown: drain HTTP, stop scheduler, close store.
func (s *Server) Shutdown(ctx context.Context) error {
	log := logger.Named("api")
	log.Info("shutting down server")

	s.scheduler.Stop()

	if err := s.taskMgr.Shutdown(ctx); err != nil {
		log.Warn("task manager shutdown", zap.Error(err))
	}

	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil {
			log.Error("http shutdown", zap.Error(err))
			return err
		}
	}

	if err := s.store.Close(); err != nil {
		log.Error("store close", zap.Error(err))
	}

	return nil
}

func (s *Server) registerWSHandlers() {
	topics := []string{
		eventbus.TopicTaskProgress,
		eventbus.TopicTaskCompleted,
		eventbus.TopicAgentIdentified,
		eventbus.TopicVulnDetected,
	}
	for _, topic := range topics {
		t := topic
		s.bus.Subscribe(t, func(_ context.Context, ev eventbus.Event) {
			eventTime := time.Now().UTC()
			s.persistTaskEvent(context.Background(), t, ev.Payload, eventTime)
			s.wsHub.Broadcast(WSMessage{
				Type:    t,
				Payload: ev.Payload,
				Time:    eventTime.Format(time.RFC3339),
			})
		})
	}
}
