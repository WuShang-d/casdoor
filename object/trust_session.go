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

type TrustSession struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`

	User                   string  `xorm:"varchar(100) index" json:"user"`
	Service                string  `xorm:"varchar(100) index" json:"service"`
	ModelId                string  `xorm:"varchar(200)" json:"modelId"`
	Policy                 string  `xorm:"varchar(100)" json:"policy"`
	AttestationStatus      string  `xorm:"varchar(100)" json:"attestationStatus"`
	Decision               string  `xorm:"varchar(100)" json:"decision"`
	EnvHash                string  `xorm:"varchar(128)" json:"envHash"`
	CbtDigest              string  `xorm:"varchar(128)" json:"cbtDigest"`
	RiskScore              float64 `json:"riskScore"`
	FreshnessAgeSeconds    int     `json:"freshnessAgeSeconds"`
	IssuedAt               string  `xorm:"varchar(100)" json:"issuedAt"`
	ExpiresAt              string  `xorm:"varchar(100)" json:"expiresAt"`
	LastVerifiedTime       string  `xorm:"varchar(100)" json:"lastVerifiedTime"`
	NextRefreshTime        string  `xorm:"varchar(100)" json:"nextRefreshTime"`
	RefreshIntervalSeconds int     `json:"refreshIntervalSeconds"`
	Assertion              string  `xorm:"varchar(500)" json:"assertion"`
	ErrorCode              string  `xorm:"varchar(100)" json:"errorCode"`
	ErrorMessage           string  `xorm:"varchar(500)" json:"errorMessage"`
	IsValid                bool    `json:"isValid"`
}

func GetTrustSessionCount(owner, user, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	if user != "" {
		session = session.And("user = ?", user)
	}
	return session.Count(&TrustSession{})
}

func GetTrustSessions(owner, user string) ([]*TrustSession, error) {
	sessions := []*TrustSession{}
	session := ormer.Engine.Desc("updated_time")
	if owner != "" {
		session = session.And("owner = ?", owner)
	}
	if user != "" {
		session = session.And("user = ?", user)
	}
	err := session.Find(&sessions)
	if err != nil {
		return sessions, err
	}
	return sessions, nil
}

func getTrustSession(owner string, name string) (*TrustSession, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	session := TrustSession{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&session)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &session, nil
}

func GetTrustSession(id string) (*TrustSession, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getTrustSession(owner, name)
}

func GetTrustSessionByName(owner string, name string) (*TrustSession, error) {
	return getTrustSession(owner, name)
}

func GetLatestTrustSession(owner, user, service string) (*TrustSession, error) {
	session := TrustSession{}
	query := ormer.Engine.Where("owner = ? and user = ?", owner, user)
	if service != "" {
		query = query.And("service = ?", service)
	}
	existed, err := query.Desc("updated_time").Get(&session)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &session, nil
}

func AddTrustSession(session *TrustSession) (bool, error) {
	if session.Name == "" {
		session.Name = util.GenerateId()
	}
	if session.CreatedTime == "" {
		session.CreatedTime = util.GetCurrentTime()
	}
	session.UpdatedTime = util.GetCurrentTime()
	if session.IssuedAt == "" {
		session.IssuedAt = session.UpdatedTime
	}

	affected, err := ormer.Engine.Insert(session)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func UpdateTrustSession(id string, session *TrustSession) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	oldSession, err := getTrustSession(owner, name)
	if err != nil {
		return false, err
	}
	if oldSession == nil {
		return false, nil
	}
	if session.CreatedTime == "" {
		session.CreatedTime = oldSession.CreatedTime
	}
	if session.IssuedAt == "" {
		session.IssuedAt = oldSession.IssuedAt
	}
	session.UpdatedTime = util.GetCurrentTime()

	affected, err := ormer.Engine.ID(core.PK{owner, name}).AllCols().Update(session)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func DeleteTrustSession(session *TrustSession) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{session.Owner, session.Name}).Delete(&TrustSession{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func (session *TrustSession) GetId() string {
	return fmt.Sprintf("%s/%s", session.Owner, session.Name)
}
