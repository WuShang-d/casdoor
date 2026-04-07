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

package object

import (
	"fmt"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

const (
	DefaultTrustPolicyName             = "trust-policy-default"
	DefaultTrustRefreshIntervalSeconds = 120
)

type TrustPolicy struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"varchar(500)" json:"description"`

	Service                string  `xorm:"varchar(100)" json:"service"`
	VerifierUrl            string  `xorm:"varchar(500)" json:"verifierUrl"`
	MaxFreshnessSeconds    int     `json:"maxFreshnessSeconds"`
	RefreshIntervalSeconds int     `json:"refreshIntervalSeconds"`
	FreshnessTauSeconds    int     `json:"freshnessTauSeconds"`
	MaxFreshnessRisk       float64 `json:"maxFreshnessRisk"`
	AllowRiskThreshold     float64 `json:"allowRiskThreshold"`
	StepUpRiskThreshold    float64 `json:"stepUpRiskThreshold"`
	DataSensitivity        float64 `json:"dataSensitivity"`
	ContextRisk            float64 `json:"contextRisk"`
	DataSensitivityWeight  float64 `json:"dataSensitivityWeight"`
	ContextRiskWeight      float64 `json:"contextRiskWeight"`
	FreshnessRiskWeight    float64 `json:"freshnessRiskWeight"`
	IntegrityRiskWeight    float64 `json:"integrityRiskWeight"`
	RequiredVerifierStatus string  `xorm:"varchar(100)" json:"requiredVerifierStatus"`
	IsFailSafeIntegrity    bool    `json:"isFailSafeIntegrity"`
	IsFailSafeFreshness    bool    `json:"isFailSafeFreshness"`
	IsEnabled              bool    `json:"isEnabled"`
}

func NewDefaultTrustPolicy(owner string) *TrustPolicy {
	return &TrustPolicy{
		Owner:                  owner,
		Name:                   DefaultTrustPolicyName,
		CreatedTime:            util.GetCurrentTime(),
		UpdatedTime:            util.GetCurrentTime(),
		DisplayName:            "Default Trust Policy",
		Description:            "Risk-aware remote attestation policy for the protected AI inference service.",
		Service:                DefaultProtectedServiceName,
		MaxFreshnessSeconds:    DefaultTrustRefreshIntervalSeconds,
		RefreshIntervalSeconds: DefaultTrustRefreshIntervalSeconds,
		FreshnessTauSeconds:    300,
		MaxFreshnessRisk:       0.95,
		AllowRiskThreshold:     0.35,
		StepUpRiskThreshold:    0.7,
		DataSensitivity:        0.2,
		ContextRisk:            0.05,
		DataSensitivityWeight:  0.2,
		ContextRiskWeight:      0.2,
		FreshnessRiskWeight:    0.4,
		IntegrityRiskWeight:    1.0,
		RequiredVerifierStatus: "verified",
		IsFailSafeIntegrity:    true,
		IsFailSafeFreshness:    true,
		IsEnabled:              true,
	}
}

func NormalizeTrustPolicy(policy *TrustPolicy) {
	if policy.MaxFreshnessSeconds <= 0 {
		policy.MaxFreshnessSeconds = DefaultTrustRefreshIntervalSeconds
	}
	if policy.RefreshIntervalSeconds <= 0 {
		policy.RefreshIntervalSeconds = DefaultTrustRefreshIntervalSeconds
	}
	if policy.FreshnessTauSeconds <= 0 {
		policy.FreshnessTauSeconds = 300
	}
	if policy.MaxFreshnessRisk <= 0 {
		policy.MaxFreshnessRisk = 0.95
	}
	if policy.AllowRiskThreshold <= 0 {
		policy.AllowRiskThreshold = 0.35
	}
	if policy.StepUpRiskThreshold <= 0 {
		policy.StepUpRiskThreshold = 0.7
	}
	if policy.DataSensitivityWeight <= 0 {
		policy.DataSensitivityWeight = 0.2
	}
	if policy.ContextRiskWeight <= 0 {
		policy.ContextRiskWeight = 0.2
	}
	if policy.FreshnessRiskWeight <= 0 {
		policy.FreshnessRiskWeight = 0.4
	}
	if policy.IntegrityRiskWeight <= 0 {
		policy.IntegrityRiskWeight = 1.0
	}
	if policy.RequiredVerifierStatus == "" {
		policy.RequiredVerifierStatus = "verified"
	}
}

func GetTrustPolicyCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&TrustPolicy{})
}

func GetTrustPolicies(owner string) ([]*TrustPolicy, error) {
	policies := []*TrustPolicy{}
	err := ormer.Engine.Desc("created_time").Find(&policies, &TrustPolicy{Owner: owner})
	if err != nil {
		return policies, err
	}
	for _, policy := range policies {
		NormalizeTrustPolicy(policy)
	}
	return policies, nil
}

func GetPaginationTrustPolicies(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*TrustPolicy, error) {
	policies := []*TrustPolicy{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&policies)
	if err != nil {
		return policies, err
	}
	for _, policy := range policies {
		NormalizeTrustPolicy(policy)
	}
	return policies, nil
}

func getTrustPolicy(owner string, name string) (*TrustPolicy, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	policy := TrustPolicy{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&policy)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}

	NormalizeTrustPolicy(&policy)
	return &policy, nil
}

func GetTrustPolicy(id string) (*TrustPolicy, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getTrustPolicy(owner, name)
}

func GetTrustPolicyByName(owner string, name string) (*TrustPolicy, error) {
	return getTrustPolicy(owner, name)
}

func AddTrustPolicy(policy *TrustPolicy) (bool, error) {
	if policy.CreatedTime == "" {
		policy.CreatedTime = util.GetCurrentTime()
	}
	policy.UpdatedTime = util.GetCurrentTime()
	NormalizeTrustPolicy(policy)

	affected, err := ormer.Engine.Insert(policy)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func UpdateTrustPolicy(id string, policy *TrustPolicy) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	oldPolicy, err := getTrustPolicy(owner, name)
	if err != nil {
		return false, err
	}
	if oldPolicy == nil {
		return false, nil
	}

	if policy.CreatedTime == "" {
		policy.CreatedTime = oldPolicy.CreatedTime
	}
	policy.UpdatedTime = util.GetCurrentTime()
	NormalizeTrustPolicy(policy)

	affected, err := ormer.Engine.ID(core.PK{owner, name}).AllCols().Update(policy)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func UpsertTrustPolicy(policy *TrustPolicy) (bool, error) {
	oldPolicy, err := getTrustPolicy(policy.Owner, policy.Name)
	if err != nil {
		return false, err
	}
	if oldPolicy == nil {
		return AddTrustPolicy(policy)
	}
	return UpdateTrustPolicy(policy.GetId(), policy)
}

func DeleteTrustPolicy(policy *TrustPolicy) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{policy.Owner, policy.Name}).Delete(&TrustPolicy{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func (policy *TrustPolicy) GetId() string {
	return fmt.Sprintf("%s/%s", policy.Owner, policy.Name)
}
