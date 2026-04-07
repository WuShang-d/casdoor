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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const (
	TrustErrorEvidenceInvalid      = "evidence_invalid"
	TrustErrorFreshnessExpired     = "freshness_expired"
	TrustErrorRiskStepUpRequired   = "risk_stepup_required"
	TrustErrorSessionNotFound      = "trust_session_not_found"
	TrustErrorServicePolicyMissing = "service_policy_missing"
	TrustErrorJwtInvalid           = "jwt_invalid"
)

type TrustError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewTrustError(code string, message string) *TrustError {
	return &TrustError{Code: code, Message: message}
}

func (e *TrustError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type TrustRequest struct {
	Owner           string          `json:"owner"`
	Service         string          `json:"service"`
	SessionId       string          `json:"sessionId"`
	ModelId         string          `json:"modelId"`
	Evidence        string          `json:"evidence"`
	Timestamp       string          `json:"timestamp"`
	Nonce           string          `json:"nonce"`
	EnvHash         string          `json:"envHash"`
	CbtDigest       string          `json:"cbtDigest"`
	Assertion       string          `json:"assertion"`
	ContextRisk     float64         `json:"contextRisk"`
	DataSensitivity float64         `json:"dataSensitivity"`
	Layers          []EvidenceLayer `json:"layers"`
	Payload         json.RawMessage `json:"payload"`
}

type TrustStatus struct {
	CurrentUser      string                   `json:"currentUser"`
	TargetService    string                   `json:"targetService"`
	ModelId          string                   `json:"modelId"`
	Session          *object.TrustSession     `json:"session"`
	Service          *object.ProtectedService `json:"service"`
	Policy           *object.TrustPolicy      `json:"policy"`
	Verification     *AttestationVerification `json:"verification"`
	GatewayDecision  string                   `json:"gatewayDecision"`
	GatewayErrorCode string                   `json:"gatewayErrorCode"`
}

type GatewayProxyResult struct {
	Decision string          `json:"decision"`
	Service  string          `json:"service"`
	ModelId  string          `json:"modelId"`
	Response json.RawMessage `json:"response,omitempty"`
	Message  string          `json:"message,omitempty"`
}

func InitTrustSession(user *object.User, req *TrustRequest) (*TrustStatus, *TrustError, error) {
	userId := util.GetId(user.Owner, user.Name)
	protectedService, policy, trustErr, err := resolveServiceAndPolicy(user, req)
	if trustErr != nil || err != nil {
		return nil, trustErr, err
	}

	now := time.Now()
	refreshInterval := policy.RefreshIntervalSeconds
	session := &object.TrustSession{
		Owner:                  protectedService.Owner,
		Name:                   util.GenerateId(),
		CreatedTime:            util.GetCurrentTime(),
		UpdatedTime:            util.GetCurrentTime(),
		User:                   userId,
		Service:                protectedService.Name,
		ModelId:                getRequestModelId(req, protectedService),
		Policy:                 policy.Name,
		AttestationStatus:      "pending",
		Decision:               "Pending",
		IssuedAt:               util.Time2String(now),
		ExpiresAt:              util.Time2String(now.Add(time.Duration(policy.MaxFreshnessSeconds) * time.Second)),
		NextRefreshTime:        util.Time2String(now.Add(time.Duration(refreshInterval) * time.Second)),
		RefreshIntervalSeconds: refreshInterval,
		IsValid:                false,
	}

	_, err = object.AddTrustSession(session)
	if err != nil {
		return nil, nil, err
	}

	return buildTrustStatus(user, protectedService, policy, session, nil), nil, nil
}

func VerifyTrustSession(user *object.User, req *TrustRequest) (*TrustStatus, *TrustError, error) {
	userId := util.GetId(user.Owner, user.Name)
	session, trustErr, err := resolveTrustSession(userId, req)
	if trustErr != nil || err != nil {
		return nil, trustErr, err
	}

	protectedService, policy, trustErr, err := resolveServiceAndPolicyForSession(user, req, session)
	if trustErr != nil || err != nil {
		return nil, trustErr, err
	}

	evidence := buildAttestationEvidence(userId, req, session, protectedService)
	verification, verifyErr, err := VerifyAttestationEvidence(policy, evidence)
	if err != nil {
		return nil, nil, err
	}
	if verification == nil {
		verification = &AttestationVerification{Status: "invalid", VerifiedAt: util.GetCurrentTime(), ErrorCode: TrustErrorEvidenceInvalid}
	}

	updateSessionFromVerification(session, protectedService, policy, req, verification, verifyErr)
	_, err = object.UpdateTrustSession(session.GetId(), session)
	if err != nil {
		return nil, nil, err
	}

	err = addAttestationRecord(session, verification, req)
	if err != nil {
		return nil, nil, err
	}

	status := buildTrustStatus(user, protectedService, policy, session, verification)
	if session.ErrorCode != "" && session.Decision != "Allow" {
		return status, NewTrustError(session.ErrorCode, session.ErrorMessage), nil
	}
	return status, nil, nil
}

func RefreshTrustSession(user *object.User, req *TrustRequest) (*TrustStatus, *TrustError, error) {
	if req == nil {
		req = &TrustRequest{}
	}
	return VerifyTrustSession(user, req)
}

func GetTrustStatus(user *object.User, owner string, serviceName string, sessionId string) (*TrustStatus, *TrustError, error) {
	req := &TrustRequest{
		Owner:     owner,
		Service:   serviceName,
		SessionId: sessionId,
	}

	userId := util.GetId(user.Owner, user.Name)
	session, trustErr, err := resolveTrustSession(userId, req)
	if trustErr != nil || err != nil {
		return nil, trustErr, err
	}

	protectedService, policy, trustErr, err := resolveServiceAndPolicyForSession(user, req, session)
	if trustErr != nil || err != nil {
		return nil, trustErr, err
	}

	updateSessionFreshness(session, policy)
	return buildTrustStatus(user, protectedService, policy, session, nil), nil, nil
}

func ValidateGatewayAccess(user *object.User, accessToken string, req *TrustRequest) (*TrustStatus, *TrustError, error) {
	if err := validateCasdoorJwt(user, accessToken); err != nil {
		return nil, err, nil
	}

	status, trustErr, err := GetTrustStatus(user, req.Owner, req.Service, req.SessionId)
	if trustErr != nil || err != nil {
		return status, trustErr, err
	}

	session := status.Session
	if req.Assertion != "" && req.Assertion != session.Assertion {
		return status, NewTrustError(TrustErrorEvidenceInvalid, "trust assertion does not match the trust session"), nil
	}
	if session.Decision == "StepUp" {
		return status, NewTrustError(TrustErrorRiskStepUpRequired, session.ErrorMessage), nil
	}
	if !session.IsValid || session.Decision != "Allow" {
		code := session.ErrorCode
		if code == "" {
			code = TrustErrorEvidenceInvalid
		}
		return status, NewTrustError(code, session.ErrorMessage), nil
	}
	if session.ErrorCode == TrustErrorFreshnessExpired {
		return status, NewTrustError(TrustErrorFreshnessExpired, session.ErrorMessage), nil
	}

	status.GatewayDecision = "Allow"
	return status, nil, nil
}

func ProxyProtectedAiService(user *object.User, accessToken string, req *TrustRequest) (*GatewayProxyResult, *TrustError, error) {
	status, trustErr, err := ValidateGatewayAccess(user, accessToken, req)
	if trustErr != nil || err != nil {
		if status != nil {
			status.GatewayDecision = "Deny"
			if trustErr != nil {
				status.GatewayErrorCode = trustErr.Code
			}
		}
		return nil, trustErr, err
	}

	if status.Service.Endpoint == "" {
		mockBody, _ := json.Marshal(map[string]interface{}{
			"message":       "mock AI inference allowed by Trust Gateway",
			"currentUser":   status.CurrentUser,
			"service":       status.TargetService,
			"modelId":       status.ModelId,
			"trustSession":  status.Session.Name,
			"trustDecision": status.Session.Decision,
		})
		return &GatewayProxyResult{
			Decision: "Allow",
			Service:  status.TargetService,
			ModelId:  status.ModelId,
			Response: mockBody,
			Message:  "mock AI inference response",
		}, nil, nil
	}

	body := req.Payload
	if len(body) == 0 {
		body = []byte("{}")
	}
	httpReq, err := http.NewRequest(http.MethodPost, status.Service.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("X-Trust-Session", status.Session.Name)
	httpReq.Header.Set("X-Trust-Assertion", status.Session.Assertion)

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, NewTrustError(TrustErrorEvidenceInvalid, fmt.Sprintf("protected service returned HTTP %d", resp.StatusCode)), nil
	}

	return &GatewayProxyResult{
		Decision: "Allow",
		Service:  status.TargetService,
		ModelId:  status.ModelId,
		Response: json.RawMessage(respBody),
	}, nil, nil
}

func resolveServiceAndPolicy(user *object.User, req *TrustRequest) (*object.ProtectedService, *object.TrustPolicy, *TrustError, error) {
	if req == nil {
		req = &TrustRequest{}
	}

	owner := req.Owner
	if owner == "" {
		owner = user.Owner
	}
	serviceName := req.Service
	if serviceName == "" {
		serviceName = object.DefaultProtectedServiceName
	}

	protectedService, err := object.GetProtectedServiceByName(owner, serviceName)
	if err != nil {
		return nil, nil, nil, err
	}
	if protectedService == nil && serviceName == object.DefaultProtectedServiceName {
		protectedService, err = object.GetProtectedServiceByName("built-in", serviceName)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if protectedService == nil || !protectedService.IsEnabled {
		return nil, nil, NewTrustError(TrustErrorServicePolicyMissing, "protected service or policy is missing"), nil
	}

	policyName := protectedService.TrustPolicy
	if policyName == "" {
		policyName = object.DefaultTrustPolicyName
	}
	policy, err := object.GetTrustPolicyByName(protectedService.Owner, policyName)
	if err != nil {
		return nil, nil, nil, err
	}
	if policy == nil || !policy.IsEnabled {
		return nil, nil, NewTrustError(TrustErrorServicePolicyMissing, "trust policy is missing or disabled"), nil
	}
	object.NormalizeTrustPolicy(policy)

	return protectedService, policy, nil, nil
}

func resolveServiceAndPolicyForSession(user *object.User, req *TrustRequest, session *object.TrustSession) (*object.ProtectedService, *object.TrustPolicy, *TrustError, error) {
	if req == nil {
		req = &TrustRequest{}
	}
	req.Owner = session.Owner
	if req.Service == "" {
		req.Service = session.Service
	}
	return resolveServiceAndPolicy(user, req)
}

func resolveTrustSession(userId string, req *TrustRequest) (*object.TrustSession, *TrustError, error) {
	if req == nil {
		req = &TrustRequest{}
	}

	var session *object.TrustSession
	var err error
	if req.SessionId != "" {
		owner := req.Owner
		if owner == "" {
			owner = "built-in"
		}
		session, err = object.GetTrustSessionByName(owner, req.SessionId)
		if session == nil && req.Owner == "" {
			session, err = object.GetTrustSessionByName("built-in", req.SessionId)
		}
	} else {
		owner := req.Owner
		if owner == "" {
			owner = "built-in"
		}
		session, err = object.GetLatestTrustSession(owner, userId, req.Service)
	}
	if err != nil {
		return nil, nil, err
	}
	if session == nil || session.User != userId {
		return nil, NewTrustError(TrustErrorSessionNotFound, "trust session not found"), nil
	}
	return session, nil, nil
}

func buildAttestationEvidence(userId string, req *TrustRequest, session *object.TrustSession, protectedService *object.ProtectedService) *AttestationEvidence {
	timestamp := req.Timestamp
	if timestamp == "" {
		timestamp = util.GetCurrentTime()
	}
	modelId := req.ModelId
	if modelId == "" {
		modelId = session.ModelId
	}
	if modelId == "" {
		modelId = protectedService.ModelId
	}

	return &AttestationEvidence{
		Owner:           session.Owner,
		User:            userId,
		Service:         protectedService.Name,
		SessionId:       session.Name,
		ModelId:         modelId,
		Evidence:        req.Evidence,
		Timestamp:       timestamp,
		Nonce:           req.Nonce,
		EnvHash:         req.EnvHash,
		CbtDigest:       req.CbtDigest,
		ContextRisk:     req.ContextRisk,
		DataSensitivity: req.DataSensitivity,
		Layers:          req.Layers,
	}
}

func updateSessionFromVerification(session *object.TrustSession, protectedService *object.ProtectedService, policy *object.TrustPolicy, req *TrustRequest, verification *AttestationVerification, verifyErr *TrustError) {
	verifiedAt := parseTimeOrNow(verification.VerifiedAt)
	attestedAt := parseTimeOrNow(verification.AttestedAt)
	if attestedAt.After(verifiedAt) {
		attestedAt = verifiedAt
	}

	freshnessAge := int(verifiedAt.Sub(attestedAt).Seconds())
	if freshnessAge < 0 {
		freshnessAge = 0
	}
	freshnessRisk := 1 - math.Exp(-float64(freshnessAge)/float64(policy.FreshnessTauSeconds))
	integrityRisk := 0.0
	errorCode := ""
	errorMessage := ""

	if verifyErr != nil {
		errorCode = verifyErr.Code
		errorMessage = verifyErr.Message
	}

	expectedStatus := policy.RequiredVerifierStatus
	if expectedStatus == "" {
		expectedStatus = "verified"
	}
	if verification.Status != expectedStatus {
		integrityRisk = 1.0
		if errorCode == "" {
			errorCode = TrustErrorEvidenceInvalid
			errorMessage = "verifier status is not verified"
		}
	}
	if protectedService.ExpectedEnvHash != "" && protectedService.ExpectedEnvHash != verification.EnvHash {
		integrityRisk = 1.0
		errorCode = TrustErrorEvidenceInvalid
		errorMessage = "env_hash does not match protected service policy"
	}

	dataSensitivity := policy.DataSensitivity
	if req.DataSensitivity > 0 {
		dataSensitivity = req.DataSensitivity
	}
	contextRisk := policy.ContextRisk
	if req.ContextRisk > 0 {
		contextRisk = req.ContextRisk
	}
	riskScore := policy.DataSensitivityWeight*dataSensitivity +
		policy.ContextRiskWeight*contextRisk +
		policy.FreshnessRiskWeight*freshnessRisk +
		policy.IntegrityRiskWeight*integrityRisk

	decision := "Allow"
	if policy.IsFailSafeIntegrity && integrityRisk > 0 {
		decision = "Deny"
	} else if policy.IsFailSafeFreshness && (freshnessAge > policy.MaxFreshnessSeconds || freshnessRisk > policy.MaxFreshnessRisk) {
		decision = "Deny"
		errorCode = TrustErrorFreshnessExpired
		errorMessage = "attestation freshness window expired"
	} else if riskScore < policy.AllowRiskThreshold {
		decision = "Allow"
	} else if riskScore < policy.StepUpRiskThreshold {
		decision = "StepUp"
		errorCode = TrustErrorRiskStepUpRequired
		errorMessage = "risk score requires step-up authentication"
	} else {
		decision = "Deny"
		errorCode = TrustErrorRiskStepUpRequired
		errorMessage = "risk score exceeds deny threshold"
	}

	session.ModelId = getRequestModelId(req, protectedService)
	session.AttestationStatus = verification.Status
	session.Decision = decision
	session.EnvHash = verification.EnvHash
	session.CbtDigest = computeCbtDigest(session.User, protectedService.GetId(), session.ModelId, verification.EnvHash, policy.Name, verification.AttestedAt)
	session.RiskScore = math.Round(riskScore*10000) / 10000
	session.FreshnessAgeSeconds = freshnessAge
	session.LastVerifiedTime = util.Time2String(verifiedAt)
	session.NextRefreshTime = util.Time2String(verifiedAt.Add(time.Duration(policy.RefreshIntervalSeconds) * time.Second))
	session.ExpiresAt = util.Time2String(attestedAt.Add(time.Duration(policy.MaxFreshnessSeconds) * time.Second))
	session.RefreshIntervalSeconds = policy.RefreshIntervalSeconds
	session.Assertion = buildTrustAssertion(session.Name, session.CbtDigest)
	session.ErrorCode = errorCode
	session.ErrorMessage = errorMessage
	session.IsValid = decision == "Allow" && errorCode == ""
}

func updateSessionFreshness(session *object.TrustSession, policy *object.TrustPolicy) {
	if session == nil || session.LastVerifiedTime == "" {
		return
	}
	lastVerifiedTime := parseTimeOrNow(session.LastVerifiedTime)
	age := int(time.Since(lastVerifiedTime).Seconds())
	if age < 0 {
		age = 0
	}
	session.FreshnessAgeSeconds = age
	if age > policy.MaxFreshnessSeconds {
		session.IsValid = false
		session.Decision = "Deny"
		session.ErrorCode = TrustErrorFreshnessExpired
		session.ErrorMessage = "trust session freshness window expired"
	}
}

func addAttestationRecord(session *object.TrustSession, verification *AttestationVerification, req *TrustRequest) error {
	evidenceSummary, _ := json.Marshal(map[string]interface{}{
		"nonce":     req.Nonce,
		"timestamp": req.Timestamp,
		"layers":    req.Layers,
		"evidence":  req.Evidence,
	})

	record := &object.AttestationRecord{
		Owner:               session.Owner,
		User:                session.User,
		Service:             session.Service,
		SessionId:           session.Name,
		ModelId:             session.ModelId,
		AttestationStatus:   session.AttestationStatus,
		Decision:            session.Decision,
		EnvHash:             session.EnvHash,
		CbtDigest:           session.CbtDigest,
		EvidenceDigest:      verification.EvidenceDigest,
		FreshnessAgeSeconds: session.FreshnessAgeSeconds,
		RiskScore:           session.RiskScore,
		Verifier:            verification.Verifier,
		ErrorCode:           session.ErrorCode,
		ErrorMessage:        session.ErrorMessage,
		VerifiedTime:        session.LastVerifiedTime,
		EvidenceSummary:     string(evidenceSummary),
	}

	_, err := object.AddAttestationRecord(record)
	return err
}

func buildTrustStatus(user *object.User, protectedService *object.ProtectedService, policy *object.TrustPolicy, session *object.TrustSession, verification *AttestationVerification) *TrustStatus {
	return &TrustStatus{
		CurrentUser:   util.GetId(user.Owner, user.Name),
		TargetService: protectedService.Name,
		ModelId:       session.ModelId,
		Session:       session,
		Service:       protectedService,
		Policy:        policy,
		Verification:  verification,
	}
}

func validateCasdoorJwt(user *object.User, accessToken string) *TrustError {
	if accessToken == "" {
		return NewTrustError(TrustErrorJwtInvalid, "Casdoor access token is empty")
	}

	application, err := object.GetApplicationByUser(user)
	if err != nil {
		return NewTrustError(TrustErrorJwtInvalid, err.Error())
	}
	if application == nil {
		return NewTrustError(TrustErrorJwtInvalid, "Casdoor application is missing")
	}

	if application.TokenFormat == "JWT-Standard" {
		_, err = object.ParseStandardJwtTokenByApplication(accessToken, application)
	} else {
		_, err = object.ParseJwtTokenByApplication(accessToken, application)
	}
	if err != nil {
		return NewTrustError(TrustErrorJwtInvalid, err.Error())
	}

	return nil
}

func getRequestModelId(req *TrustRequest, protectedService *object.ProtectedService) string {
	if req != nil && req.ModelId != "" {
		return req.ModelId
	}
	return protectedService.ModelId
}

func computeCbtDigest(userId string, serviceId string, modelId string, envHash string, policy string, timestamp string) string {
	return hashString(strings.Join([]string{userId, serviceId, modelId, envHash, policy, timestamp}, "|"))
}

func buildTrustAssertion(sessionId string, cbtDigest string) string {
	raw := fmt.Sprintf("%s.%s", sessionId, cbtDigest)
	return "trust_" + base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func parseTimeOrNow(value string) time.Time {
	if value == "" {
		return time.Now()
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Now()
	}
	return t
}
