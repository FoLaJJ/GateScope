package main

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AutoScan/agentscan/internal/api"
	"github.com/AutoScan/agentscan/internal/core/config"
	"github.com/AutoScan/agentscan/internal/core/eventbus"
	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/AutoScan/agentscan/internal/engine"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/AutoScan/agentscan/web"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var cfgFile string

func main() {
	rootCmd := &cobra.Command{
		Use:   "agentscan",
		Short: "ClawScan - OpenClaw 暴露面扫描与漏洞核验平台",
		Long:  "ClawScan 面向 OpenClaw 场景的暴露面检测与漏洞核验系统",
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件路径 (默认搜索 ./config.yaml, ./configs/, ./_data/, /etc/agentscan/)")

	rootCmd.AddCommand(serverCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(migrateCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	return config.Load(cfgFile)
}

func initLogger(cfg *config.Config) {
	logger.Init(logger.Options{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		File:   cfg.Log.File,
	})
}

func serverCmd() *cobra.Command {
	var (
		host     string
		port     int
		dbDriver string
		dbDSN    string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "启动 ClawScan Web 服务",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			if cmd.Flags().Changed("host") {
				cfg.Server.Host = host
			}
			if cmd.Flags().Changed("port") {
				cfg.Server.Port = port
			}
			if cmd.Flags().Changed("db-driver") {
				cfg.Database.Driver = dbDriver
			}
			if cmd.Flags().Changed("db-dsn") {
				cfg.Database.DSN = dbDSN
			}

			initLogger(cfg)
			defer logger.Sync()
			log := logger.Named("main")

			s, err := store.NewGormStore(cfg)
			if err != nil {
				return fmt.Errorf("database: %w", err)
			}
			if err := s.AutoMigrate(); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			bus := eventbus.NewLocal()

			var frontendFS fs.FS
			if sub, err := fs.Sub(web.DistFS, "dist"); err == nil {
				frontendFS = sub
			}
			srv := api.NewServer(cfg, s, bus, frontendFS)

			// Graceful shutdown
			errCh := make(chan error, 1)
			go func() {
				if err := srv.Start(); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

			select {
			case sig := <-quit:
				log.Info("received shutdown signal", zap.String("signal", sig.String()))
			case err := <-errCh:
				log.Error("server error", zap.Error(err))
				return err
			}

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Error("shutdown failed", zap.Error(err))
				return err
			}

			log.Info("server stopped gracefully")
			return nil
		},
	}

	cmd.Flags().StringVarP(&host, "host", "H", "", "监听地址 (覆盖配置)")
	cmd.Flags().IntVarP(&port, "port", "p", 0, "监听端口 (覆盖配置)")
	cmd.Flags().StringVar(&dbDriver, "db-driver", "", "数据库驱动 (覆盖配置)")
	cmd.Flags().StringVar(&dbDSN, "db-dsn", "", "数据库连接字符串 (覆盖配置)")

	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "快速扫描目标 (CLI 模式，不依赖数据库)",
		Long:  "target 支持: 单IP, CIDR, 逗号分隔多段",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Init(logger.Options{Level: "warn", Format: "console"})
			defer logger.Sync()

			target := args[0]
			ports, _ := cmd.Flags().GetIntSlice("ports")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			concurrency, _ := cmd.Flags().GetInt("concurrency")
			depth, _ := cmd.Flags().GetString("depth")
			useMDNS, _ := cmd.Flags().GetBool("mdns")
			l1ScanMode, _ := cmd.Flags().GetString("l1-scan-mode")

			if l1ScanMode != "connect" && l1ScanMode != "syn" {
				return fmt.Errorf("invalid l1 scan mode %q: must be connect or syn", l1ScanMode)
			}

			fmt.Println("╔══════════════════════════════════════════════════════════╗")
			fmt.Println("║            ClawScan  v0.4.0                             ║")
			fmt.Println("║    AI Agent Discovery & Security Audit                   ║")
			fmt.Println("╚══════════════════════════════════════════════════════════╝")
			fmt.Println()

			bus := eventbus.NewLocal()
			pipeline := engine.NewPipeline(bus)
			pipeline.SetProgressCallback(func(scanned, total int, phase string) {
				pct := float64(0)
				if total > 0 {
					pct = float64(scanned) / float64(total) * 100
				}
				fmt.Printf("\r  [%s] %d/%d (%.0f%%)", phase, scanned, total, pct)
			})

			cfg := engine.PipelineConfig{
				Ports:       ports,
				ScanDepth:   models.ScanDepth(depth),
				Timeout:     timeout,
				Concurrency: concurrency,
				RateLimit:   10000,
				L1ScanMode:  l1ScanMode,
				EnableMDNS:  useMDNS,
				MDNSTimeout: 5 * time.Second,
				TaskID:      "cli-scan",
			}

			result, err := pipeline.Run(context.Background(), target, cfg)
			if err != nil {
				return err
			}

			fmt.Printf("\n\n")
			fmt.Println("╔══════════════════════════════════════════════════════════╗")
			fmt.Println("║                      扫描结果                            ║")
			fmt.Println("╚══════════════════════════════════════════════════════════╝")
			fmt.Printf("  目标: %d | 开放端口: %d | Agent: %d | 漏洞: %d\n\n",
				result.TotalScanned, result.OpenPorts, len(result.Assets), len(result.Vulnerabilities))

			riskIcon := map[models.RiskLevel]string{
				models.RiskCritical: "🔴", models.RiskHigh: "🟠",
				models.RiskMedium: "🟡", models.RiskLow: "🟢", models.RiskInfo: "🔵",
			}
			for _, a := range result.Assets {
				fmt.Printf("  %s %s:%d  type=%s ver=%s auth=%s confidence=%.0f%%\n",
					riskIcon[a.RiskLevel], a.IP, a.Port, a.AgentType, a.Version, a.AuthMode, a.Confidence)
			}

			if len(result.Vulnerabilities) > 0 {
				fmt.Println()
				fmt.Println("  ── Vulnerabilities ──")
				sevIcon := map[models.Severity]string{
					models.SeverityCritical: "🔴", models.SeverityHigh: "🟠",
					models.SeverityMedium: "🟡", models.SeverityLow: "🟢",
				}
				for _, v := range result.Vulnerabilities {
					cve := v.CVEID
					if cve == "" {
						cve = v.CheckType
					}
					fmt.Printf("  %s [%s] %s (CVSS %.1f)\n", sevIcon[v.Severity], cve, v.Title, v.CVSS)
				}
			}

			fmt.Println()
			return nil
		},
	}

	cmd.Flags().IntSliceP("ports", "P", []int{18789, 18790, 18792, 3000, 8080, 8888}, "扫描端口列表")
	cmd.Flags().DurationP("timeout", "t", 3*time.Second, "连接超时")
	cmd.Flags().IntP("concurrency", "c", 100, "并发数")
	cmd.Flags().String("depth", "l3", "扫描深度 (l1|l2|l3)")
	cmd.Flags().String("l1-scan-mode", "connect", "L1 扫描模式 (connect|syn)")
	cmd.Flags().Bool("mdns", true, "启用 mDNS 服务发现")

	return cmd
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "运行数据库迁移",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			initLogger(cfg)
			defer logger.Sync()

			s, err := store.NewGormStore(cfg)
			if err != nil {
				return fmt.Errorf("database: %w", err)
			}
			defer s.Close()

			return s.AutoMigrate()
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("ClawScan v0.4.0")
		},
	}
}
