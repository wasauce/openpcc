// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/confidentsecurity/twoway"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/ahttp"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router/api"
	opcctpm "github.com/openpcc/openpcc/tpm"
	tpmhpke "github.com/openpcc/openpcc/tpm/hpke"
	"go.opentelemetry.io/otel/codes"
)

const (
	defaultTPMDevice = "/dev/tpmrm0"
)

type RCSConfig struct {
	// TPM is tpm related config
	TPM *TPM `yaml:"tpm"`
	// Worker is compute_worker related config
	Worker *WorkerConfig `yaml:"worker"`
}

type TPM struct {
	// Simulate indicates whether the TPM is simulated. Only true during local dev
	Simulate bool `yaml:"simulate"`
	// Device is the filesystem device where the TPM lives
	Device string `yaml:"device"`
	// REKHandle is the TPM handle for the Request Encryption Key
	REKHandle uint32 `yaml:"rek_handle"`
	// SimulatorCmdAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorCmdAddress string `yaml:"simulator_cmd_address"`
	// SimulatorPlatformAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorPlatformAddress string `yaml:"simulator_platform_address"`
}

// WorkerConfig is config for talking to compute_worker
type WorkerConfig struct {
	// BinaryPath is where the compute_worker binary lives on the machine
	BinaryPath string `yaml:"binary_path"`
	// LLMBaseURL is the local url for talking to an LLM on the system
	LLMBaseURL string `yaml:"llm_base_url"`
	// Timeout is how long to wait for the compute_worker to work
	Timeout time.Duration `yaml:"timeout"`
	// BadgePublicKey is the public key counterpart to the ed25519 private key that the auth server uses to sign badges
	BadgePublicKey string `yaml:"badge_public_key"`
	// Models is the list of LLMs installed on the system
	Models []string `yaml:"models"`
}

func DefaultConfig() *RCSConfig {
	return &RCSConfig{
		TPM: &TPM{
			Simulate:  false,
			Device:    defaultTPMDevice,
			REKHandle: 0x81000000,
		},
		Worker: &WorkerConfig{
			BinaryPath: "",
			// Zero values mean we use the defaults from the computeworker flags.
			LLMBaseURL: "",
			// Set the compute worker process timeout to 5 minutes,
			// to match our default 5 minute inference timeout in the client, and the gateway.
			Timeout:        5 * time.Minute,
			BadgePublicKey: "",
			Models:         []string{},
		},
	}
}

func (s *RouterComService) generateHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := otelutil.Tracer.Start(r.Context(), "routercom.generateHandler")
	defer span.End()

	r = r.WithContext(ctx)

	requestParams, err := s.requestParams(r)
	if err != nil {
		otelutil.RecordError2(span, fmt.Errorf("failed to parse request params: %w", err))
		httpfmt.BinaryBadRequest(w, r, err.Error())
		return
	}

	// decode required inputs
	adapter := newTPMSuiteAdapter(r.Context(), s)
	receiver, err := twoway.NewMultiRequestReceiverWithCustomSuite(adapter, 0, nil, rand.Reader) // nil priv key since we're using the TPM.
	if err != nil {
		otelutil.RecordError2(span, fmt.Errorf("failed to create multi request receiver: %w", err))
		httpfmt.BinaryBadRequest(w, r, err.Error())
		return
	}

	req, opener, err := messages.DecapsulateRequest(ctx, receiver, requestParams.EncapsulatedKey, requestParams.MediaType, r.Body)
	if err != nil {
		otelutil.RecordError2(span, fmt.Errorf("failed to decapsulate request: %w", err))
		httpfmt.BinaryBadRequest(w, r, "invalid request")
		return
	}

	req = req.WithContext(ctx)

	// TODO: reverse proxy

	// for now create a hardcoded response
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader("hello world!")),
	}
	encapResp, encapRespMediaType, err := messages.EncapsulateResponse(opener, resp)
	if err != nil {
		otelutil.RecordError2(span, fmt.Errorf("failed to encapsulate response: %w", err))
		httpfmt.BinaryServerError(w, r)
		return
	}

	w.Header().Set("Content-Type", encapRespMediaType)
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, encapResp)
	if err != nil {
		otelutil.RecordError2(span, fmt.Errorf("failed to copy encapsulated response: %w", err))
		return
	}

	span.SetStatus(codes.Ok, "")
}

type RequestParams struct {
	MediaType       string
	EncapsulatedKey []byte
	CreditAmount    int64
}

// requestParams extracts the compute worker request parameters from the request and returns
// an error if these are invalid. The error is safe to return to the user and contains no technical
// information.
func (*RouterComService) requestParams(r *http.Request) (RequestParams, error) {
	// check if media type looks right.
	mediaType := r.Header.Get("Content-Type")
	if !messages.IsRequestMediaType(mediaType) {
		return RequestParams{}, errors.New("invalid media type")
	}

	// check if encapsulated key looks right.
	b64EncapKey := r.Header.Get(api.EncapsulatedKeyHeader)
	if len(b64EncapKey) == 0 || len(b64EncapKey) > 512 {
		return RequestParams{}, errors.New("invalid encapsulated key")
	}

	encapKey, err := base64.StdEncoding.DecodeString(b64EncapKey)
	if err != nil {
		return RequestParams{}, errors.New("invalid encapsulated key")
	}

	// check if credit amount and encap key looks right.
	creditAmount, err := strconv.ParseInt(r.Header.Get(ahttp.NodeCreditAmountHeader), 10, 64)
	if err != nil {
		return RequestParams{}, errors.New("invalid credit amount")
	}

	if creditAmount <= 0 {
		return RequestParams{}, errors.New("credit amount must be greater than 0")
	}

	return RequestParams{
		MediaType:       mediaType,
		EncapsulatedKey: encapKey,
		CreditAmount:    creditAmount,
	}, nil
}

type closeFunc func(ctx context.Context) int

func writeResponseForExitCode(w http.ResponseWriter, r *http.Request, exitCode int) {
	// switch exitCode {
	// case exitcodes.RequestDecapsulationCode:
	// 	httpfmt.BinaryBadRequest(w, r, "failed to decapsulate encrypted request")
	// default:
	// 	httpfmt.BinaryServerError(w, r)
	// }
	httpfmt.BinaryServerError(w, r)
}

// func (*RouterComService) handleRefundTrailer(ctx context.Context, w http.ResponseWriter, decoder *output.Decoder) {
// 	ctx, span := otelutil.Tracer.Start(ctx, "routercom.handleRefundTrailer")
// 	defer span.End()

// 	footer, hasFooter := decoder.Footer()
// 	if !hasFooter {
// 		slog.ErrorContext(ctx, "output from worker is missing footer")
// 		return
// 	}

// 	if !footer.HasRefund() {
// 		return
// 	}

// 	currencyProto, err := footer.Refund.MarshalProto()
// 	if err != nil {
// 		slog.Error("failed to marshal refund to proto", "error", err)
// 		return
// 	}
// 	b, err := proto.Marshal(currencyProto)
// 	if err != nil {
// 		slog.Error("failed to marshal refund proto to binary", "error", err)
// 		return
// 	}

// 	w.Header().Set(ahttp.NodeRefundAmountHeader, base64.StdEncoding.EncodeToString(b))
// }

type RouterComService struct {
	config   *RCSConfig
	handler  http.Handler
	evidence ev.SignedEvidenceList

	commandsWG       *sync.WaitGroup
	base64PubKey     string
	base64PubKeyName string
	base64PCRValues  string

	pubKey          kem.PublicKey
	pubKeyNameBytes []byte
	pcrValues       map[uint32][]byte

	tpmDevice transport.TPM
}

func NewRouterCom(cfg *RCSConfig, evidence ev.SignedEvidenceList, tpmDevice transport.TPM) (*RouterComService, error) {
	s := &RouterComService{
		config:     cfg,
		evidence:   evidence,
		commandsWG: &sync.WaitGroup{},
		tpmDevice:  tpmDevice,
	}

	var pubKeyBytes []byte

	// extract data required by the compute worker from the evidence.
	for _, item := range s.evidence {
		switch item.Type { //nolint:exhaustive
		case ev.TpmtPublic:
			b, err := tpmptToPubKeyBytes(item)
			if err != nil {
				return nil, fmt.Errorf("failed to extract rek public key from evidence: %w", err)
			}

			pubKeyBytes = b
			s.pubKeyNameBytes = item.Signature
			continue
		case ev.TpmQuote:
			quotePB := ev.TPMQuoteAttestation{}
			err := quotePB.UnmarshalBinary(item.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal tpm quote to protobuf: %w", err)
			}

			s.pcrValues = quotePB.PCRValues.Values
			continue
		case ev.NvidiaCCIntermediateCertificate, ev.NvidiaSwitchIntermediateCertificate:
			// Extract the intermediate certificate to identify its expiry date.
			cert, err := x509.ParseCertificate(item.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse nvidia intermediate certificate: %w", err)
			}

			slog.Info("Nvidia intermediate certificate provided in evidence",
				"subject", cert.Subject.String(),
				"not_before", cert.NotBefore,
				"not_after", cert.NotAfter)

			// Schedule router_com to shutdown when the certificate expires.
			// Until we have more data around JWT expirations, we will force compute
			// nodes to be recreated when the intermediate certificate expires
			// (since that breaks the attestation package provided to the client).
			go func() {
				// Shut down 1 minute before the certificate expires.
				// This gives the node time to notify the router that it is shutting down,
				// and finish serving any in-flight requests.
				expirationTime := cert.NotAfter.Add(-1 * time.Minute)
				slog.Info("Waiting until certificate expiry to force a shutdown",
					"not_after", cert.NotAfter,
					"expiration_time", expirationTime)

				time.Sleep(time.Until(expirationTime))
				pid := os.Getpid()
				// Send SIGTERM to ourselves to trigger a graceful shutdown.
				err := syscall.Kill(pid, syscall.SIGTERM)
				if err != nil {
					// This really shouldnt happen...
					panic("failed to kill router_com: " + err.Error())
				}
			}()
		default:
		}
	}

	if len(pubKeyBytes) == 0 {
		return nil, errors.New("failed to find public key in evidence")
	}

	if len(s.pubKeyNameBytes) == 0 {
		return nil, errors.New("failed to find public key name in evidence")
	}

	if len(s.pcrValues) == 0 {
		return nil, errors.New("failed to find pcr values in evidence")
	}

	kemID, _, _ := tpmhpke.SuiteParams()
	pubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	s.pubKey = pubKey

	goldenPCRValues := map[uint32][]byte{}
	for _, pcr := range ev.AttestPCRSelection {
		if pcr > math.MaxUint32 {
			return nil, fmt.Errorf("unexpected pcr value %d, does not fit in uint32", pcr)
		}

		val, ok := s.pcrValues[uint32(pcr)]
		if !ok {
			return nil, fmt.Errorf("config is missing pcr value %d", pcr)
		}
		goldenPCRValues[uint32(pcr)] = val
	}
	s.pcrValues = goldenPCRValues

	setupHandlers(s)

	return s, nil
}

func setupHandlers(s *RouterComService) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /_health", httpfmt.JSONHealthCheck)
	otelutil.ServeMuxHandleFunc(mux, "POST /", s.generateHandler)

	s.handler = mux
}

func (s *RouterComService) Evidence() ev.SignedEvidenceList {
	return s.evidence
}

func (s *RouterComService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Confsec-Ping") == "routercom" {
		_, err := w.Write([]byte("routercom"))
		if err != nil {
			slog.Error("failed to write ping response", "err", err)
		}
		return
	}

	s.handler.ServeHTTP(w, r)
}

func (s *RouterComService) Close() error {
	s.commandsWG.Wait()
	return nil
}

func tpmptToPubKeyBytes(evidence *ev.SignedEvidencePiece) ([]byte, error) {
	tpmtPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](evidence.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tpmpt public key: %w", err)
	}

	kemPub, err := tpmhpke.Pub(tpmtPub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tpmpt public key to hpke public key: %w", err)
	}

	b, err := kemPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to bytes: %w", err)
	}

	return b, nil
}

// tpmSuiteAdapter implements twoway.HPKESuite so we can inject our TPM based HPKE receiver
// into twoway.
type tpmSuiteAdapter struct {
	ctx context.Context
	svc *RouterComService
}

func newTPMSuiteAdapter(ctx context.Context, s *RouterComService) *tpmSuiteAdapter {
	return &tpmSuiteAdapter{
		ctx: ctx,
		svc: s,
	}
}

func (*tpmSuiteAdapter) NewSender(_ kem.PublicKey, _ []byte) (twoway.HPKESender, error) {
	panic("not implemented")
}

func (s *tpmSuiteAdapter) NewReceiver(_ kem.PrivateKey, info []byte) (twoway.HPKEReceiver, error) {
	ecdhZGgenWithTPM := func(keyInfo *tpmhpke.ECDHZGenKeyInfo, pubPoint tpm2.TPM2BECCPoint) ([]byte, error) {
		// 1. Begin TPM session.
		_, sessionSpan := otelutil.Tracer.Start(s.ctx, "computeworker.TPMHPKE.beginSession")
		sess, cleanup, err := opcctpm.PCRPolicySession(s.svc.tpmDevice, s.svc.pcrValues)
		if err != nil {
			sessionSpan.End()
			return nil, fmt.Errorf("failed to create tpm session: %w", err)
		}
		sessionSpan.End()

		defer func() {
			_, span := otelutil.Tracer.Start(s.ctx, "computeworker.TPMHPKE.cleanupSession")
			defer span.End()
			err = errors.Join(err, cleanup())
		}()

		// 3. ECDHZgen
		_, ecdhZGenSpan := otelutil.Tracer.Start(s.ctx, "computeworker.TPMHPKE.ecdhZGen")
		b, err := tpmhpke.ECDHZGen(s.svc.tpmDevice, sess, keyInfo, pubPoint)
		ecdhZGenSpan.End()
		return b, err
	}

	receiver := tpmhpke.NewReceiver(s.svc.pubKey, info, &tpmhpke.ECDHZGenKeyInfo{
		PrivKeyHandle: tpmutil.Handle(s.svc.config.TPM.REKHandle),
		PublicName: tpm2.TPM2BName{
			Buffer: s.svc.pubKeyNameBytes,
		},
	}, ecdhZGgenWithTPM)
	return &tpmReceiverAdapter{
		receiver: receiver,
	}, nil
}

func (s *tpmSuiteAdapter) Params() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return tpmhpke.SuiteParams()
}

// tpmReceiverAdapter implements twoway.HPKEReceiver so we can inject our TPM based HPKE Receiver
// into twoway.
type tpmReceiverAdapter struct {
	receiver *tpmhpke.Receiver
}

func (r *tpmReceiverAdapter) Setup(enc []byte) (twoway.HPKEOpener, error) {
	return r.receiver.Setup(enc)
}
