package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openpcc/openpcc/app"
	"github.com/openpcc/openpcc/app/httpapp"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/uuidv7"
)

type RouterComConfig struct {
	// HTTP is http server related config
	HTTP *httpapp.Config `yaml:"http"`
	// RouterCom is router_com service specific config
	RouterCom *RCSConfig `yaml:"router_com"`
	// RouterAgent is config related to registering with the router
	RouterAgent *agent.Config `yaml:"router_agent"`
	// Models is the list of LLMs installed on the system
	Models []string `yaml:"models"`
}

func main() {
	fmt.Println("Computing")

	tpmOperator := &TPMOperator{
		childKeyHandle:          0x81000000,
		primaryKeyHandle:        0x81010001,
		rekCreationTicketHandle: 0x01c0000A,
		rekCreationHashHandle:   0x01c0000B,
		attestationKeyHandle:    0x81000003,
		device:                  NewTPMInMemorySimulator(),
	}

	err := setupTPM(context.Background(), tpmOperator)
	if err != nil {
		slog.Error("TPM setup failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		err = errors.Join(err, tpmOperator.Close())
	}()

	// generate fake attestation
	evidence, err := collectFakeTPMEvidence(tpmOperator)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(" HERE EV", evidence)
	// register with router

	// start with default config and override by loading from
	// YAML file and/or environment.
	cfg := &RouterComConfig{
		HTTP:      httpapp.DefaultStreamingConfig(),
		RouterCom: DefaultConfig(),
		RouterAgent: &agent.Config{
			Tags:               []string{"test-model"},
			NodeTargetURL:      "http://localhost:3700/generate",
			NodeHealthcheckURL: "http://localhost:3700/_health",
			HeartbeatInterval:  1 * time.Minute,
			RouterBaseURL:      "http://localhost:3600",
		},
		Models: []string{"test-model"},
	}

	cfg.HTTP.Port = "3700"

	if len(cfg.Models) == 0 {
		slog.Error("Invalid config: no models provided")
	}
	for _, model := range cfg.Models {
		cfg.RouterAgent.Tags = append(cfg.RouterAgent.Tags, "model="+model)
		cfg.RouterCom.Worker.Models = append(cfg.RouterCom.Worker.Models, model)
	}

	// setup routercom as an http app
	rtrcom, err := NewRouterCom(cfg.RouterCom, evidence, *tpmOperator.device.tpmHandle)
	if err != nil {
		slog.Error("failed to create routercom service", "error", err)
		os.Exit(1)
	}

	defer func() {
		err = errors.Join(err, rtrcom.Close())
	}()

	// setup the router agent
	id, err := uuidv7.New()
	if err != nil {
		slog.Error("failed to generate uuid for routercom", "error", err)
		os.Exit(1)
	}

	rtragent, err := agent.New(id, cfg.RouterAgent, rtrcom.Evidence())
	if err != nil {
		slog.Error("failed to create new router agent", "error", err)
		os.Exit(1)
	}

	a := app.NewMulti(
		httpapp.New(cfg.HTTP, rtrcom),
		rtragent,
	)

	// run the app until it exits or signals received
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	app.Run(ctx, a, func() (context.Context, context.CancelFunc) {
		// signals received during graceful shutdown cause immediate exit
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	})

	fmt.Println("ALLDONE")

	// listen, decode, respond all in one go

}
