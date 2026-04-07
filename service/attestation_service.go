// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

type EvidenceLayer struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

type AttestationEvidence struct {
	Owner           string          `json:"owner"`
	User            string          `json:"user"`
	Service         string          `json:"service"`
	SessionId       string          `json:"sessionId"`
	ModelId         string          `json:"modelId"`
	Evidence        string          `json:"evidence"`
	Timestamp       string          `json:"timestamp"`
	Nonce           string          `json:"nonce"`
	EnvHash         string          `json:"envHash"`
	CbtDigest       string          `json:"cbtDigest"`
	ContextRisk     float64         `json:"contextRisk"`
	DataSensitivity float64         `json:"dataSensitivity"`
	Layers          []EvidenceLayer `json:"layers"`
}

type AttestationVerification struct {
	Status         string          `json:"status"`
	EnvHash        string          `json:"envHash"`
	CbtDigest      string          `json:"cbtDigest"`
	EvidenceDigest string          `json:"evidenceDigest"`
	AttestedAt     string          `json:"attestedAt"`
	VerifiedAt     string          `json:"verifiedAt"`
	Verifier       string          `json:"verifier"`
	ErrorCode      string          `json:"errorCode"`
	ErrorMessage   string          `json:"errorMessage"`
	Layers         []EvidenceLayer `json:"layers"`
}

func VerifyAttestationEvidence(policy *object.TrustPolicy, evidence *AttestationEvidence) (*AttestationVerification, *TrustError, error) {
	if evidence == nil {
		return nil, NewTrustError(TrustErrorEvidenceInvalid, "attestation evidence is empty"), nil
	}

	if policy != nil && strings.TrimSpace(policy.VerifierUrl) != "" {
		return verifyAttestationWithRemoteVerifier(policy.VerifierUrl, evidence)
	}

	return verifyAttestationWithMockVerifier(evidence), nil, nil
}

func verifyAttestationWithRemoteVerifier(verifierUrl string, evidence *AttestationEvidence) (*AttestationVerification, *TrustError, error) {
	body, err := json.Marshal(evidence)
	if err != nil {
		return nil, nil, err
	}

	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, verifierUrl, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, NewTrustError(TrustErrorEvidenceInvalid, err.Error()), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, NewTrustError(TrustErrorEvidenceInvalid, fmt.Sprintf("verifier returned HTTP %d", resp.StatusCode)), nil
	}

	verification := AttestationVerification{}
	err = json.Unmarshal(respBody, &verification)
	if err != nil {
		return nil, nil, err
	}

	if verification.Status == "" {
		verification.Status = "verified"
	}
	if verification.Verifier == "" {
		verification.Verifier = verifierUrl
	}
	if verification.VerifiedAt == "" {
		verification.VerifiedAt = util.GetCurrentTime()
	}
	if verification.AttestedAt == "" {
		verification.AttestedAt = evidence.Timestamp
	}
	if verification.AttestedAt == "" {
		verification.AttestedAt = verification.VerifiedAt
	}
	if verification.EnvHash == "" {
		verification.EnvHash = evidence.EnvHash
	}
	if verification.EnvHash == "" {
		verification.EnvHash = computeEnvHash(evidence)
	}
	if verification.EvidenceDigest == "" {
		verification.EvidenceDigest = hashString(string(body))
	}
	if len(verification.Layers) == 0 {
		verification.Layers = evidence.Layers
	}

	if verification.ErrorCode != "" || verification.Status != "verified" {
		code := verification.ErrorCode
		if code == "" {
			code = TrustErrorEvidenceInvalid
		}
		return &verification, NewTrustError(code, verification.ErrorMessage), nil
	}

	return &verification, nil, nil
}

func verifyAttestationWithMockVerifier(evidence *AttestationEvidence) *AttestationVerification {
	layers := evidence.Layers
	if len(layers) == 0 {
		layers = []EvidenceLayer{
			{Name: "code", Hash: hashString("casdoor-ai-portal-code-v1")},
			{Name: "model", Hash: hashString(evidence.ModelId)},
			{Name: "runtime", Hash: hashString("go-trust-orchestrator-v1")},
			{Name: "config", Hash: hashString("refresh=120")},
		}
		evidence.Layers = layers
	}

	status := "verified"
	errorCode := ""
	errorMessage := ""
	if strings.EqualFold(evidence.Evidence, "invalid") || strings.EqualFold(evidence.EnvHash, "invalid") {
		status = "invalid"
		errorCode = TrustErrorEvidenceInvalid
		errorMessage = "mock verifier rejected the evidence"
	}

	verifiedAt := util.GetCurrentTime()
	attestedAt := evidence.Timestamp
	if attestedAt == "" {
		attestedAt = verifiedAt
	}

	envHash := evidence.EnvHash
	if envHash == "" || envHash == "invalid" {
		envHash = computeEnvHash(evidence)
	}

	rawEvidence, _ := json.Marshal(evidence)
	return &AttestationVerification{
		Status:         status,
		EnvHash:        envHash,
		CbtDigest:      evidence.CbtDigest,
		EvidenceDigest: hashString(string(rawEvidence)),
		AttestedAt:     attestedAt,
		VerifiedAt:     verifiedAt,
		Verifier:       "mock-verifier",
		ErrorCode:      errorCode,
		ErrorMessage:   errorMessage,
		Layers:         layers,
	}
}

func computeEnvHash(evidence *AttestationEvidence) string {
	parts := []string{}
	for _, layer := range evidence.Layers {
		if layer.Hash == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s", layer.Name, layer.Hash))
	}
	sort.Strings(parts)

	if len(parts) == 0 {
		parts = append(parts,
			"model:"+evidence.ModelId,
			"service:"+evidence.Service,
			"evidence:"+evidence.Evidence,
		)
		sort.Strings(parts)
	}

	return hashString(strings.Join(parts, "|"))
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
