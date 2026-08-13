//go:build wasip1

package main

import (
	"time"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
)

// Confidential (TEE) execution support. Both handlers run inside an attested
// enclave via cre.HandlerInTee, so the oracle private key, the Data Streams
// client secret, and every derived thold secret only ever exist in enclave
// memory — never on Workflow DON nodes.

// teeConstraint pins execution to AWS Nitro in us-west-2 — the only TEE
// type/region CRE currently registers. Pinned explicitly (rather than
// cre.AnyTee) so a future TEE type or region must be adopted deliberately:
// this workflow holds a money-bearing signing key and the acceptable
// enclave set is a security decision, not a scheduling preference.
func teeConstraint() cre.TeeConstraint {
	return cre.OneOfTees{cre.Nitro{Regions: []cre.NitroRegion{cre.NitroUsWest2}}}
}

// httpSender is the outbound-HTTP seam shared by all leaf request functions.
// In TEE execution it is backed by SendRequestInTee, so requests leave
// directly from the enclave and are trusted via enclave attestation rather
// than per-node consensus (each request executes exactly once, not once per
// DON node). Now() is included so time-sensitive callers (the Chainlink HMAC
// auth timestamp, staleness checks) use the SDK's sanctioned clock — served
// through the dedicated env.now host import — instead of the WASI guest
// clock, whose behavior inside a production enclave the SDK does not define.
type httpSender interface {
	SendRequest(input *http.Request) cre.Promise[*http.Response]
	Now() time.Time
}

type teeSender struct {
	runtime cre.TeeRuntime
	client  *http.Client
	calls   int
}

func newTeeSender(runtime cre.TeeRuntime) *teeSender {
	return &teeSender{runtime: runtime, client: &http.Client{}}
}

func (s *teeSender) SendRequest(input *http.Request) cre.Promise[*http.Response] {
	s.calls++
	return s.client.SendRequestInTee(s.runtime, input)
}

func (s *teeSender) Now() time.Time {
	return s.runtime.Now()
}

// Calls reports the number of HTTP requests issued from the enclave so far,
// including every internal retry — the unit the unified-cycle budget guard
// meters.
func (s *teeSender) Calls() int {
	return s.calls
}
