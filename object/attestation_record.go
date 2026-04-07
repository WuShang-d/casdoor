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
	"github.com/casdoor/casdoor/util"
)

type AttestationRecord struct {
	Id int `xorm:"int notnull pk autoincr" json:"id"`

	Owner       string `xorm:"varchar(100) index" json:"owner"`
	Name        string `xorm:"varchar(100) index" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`

	User                string  `xorm:"varchar(100) index" json:"user"`
	Service             string  `xorm:"varchar(100) index" json:"service"`
	SessionId           string  `xorm:"varchar(100) index" json:"sessionId"`
	ModelId             string  `xorm:"varchar(200)" json:"modelId"`
	AttestationStatus   string  `xorm:"varchar(100)" json:"attestationStatus"`
	Decision            string  `xorm:"varchar(100)" json:"decision"`
	EnvHash             string  `xorm:"varchar(128)" json:"envHash"`
	CbtDigest           string  `xorm:"varchar(128)" json:"cbtDigest"`
	EvidenceDigest      string  `xorm:"varchar(128)" json:"evidenceDigest"`
	FreshnessAgeSeconds int     `json:"freshnessAgeSeconds"`
	RiskScore           float64 `json:"riskScore"`
	Verifier            string  `xorm:"varchar(500)" json:"verifier"`
	ErrorCode           string  `xorm:"varchar(100)" json:"errorCode"`
	ErrorMessage        string  `xorm:"varchar(500)" json:"errorMessage"`
	VerifiedTime        string  `xorm:"varchar(100)" json:"verifiedTime"`
	EvidenceSummary     string  `xorm:"mediumtext" json:"evidenceSummary"`
}

func GetAttestationRecordCount(owner, user, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	if user != "" {
		session = session.And("user = ?", user)
	}
	return session.Count(&AttestationRecord{})
}

func GetAttestationRecords(owner, user string) ([]*AttestationRecord, error) {
	records := []*AttestationRecord{}
	session := ormer.Engine.Desc("id")
	if owner != "" {
		session = session.And("owner = ?", owner)
	}
	if user != "" {
		session = session.And("user = ?", user)
	}
	err := session.Find(&records)
	if err != nil {
		return records, err
	}
	return records, nil
}

func GetPaginationAttestationRecords(owner, user string, offset, limit int, field, value, sortField, sortOrder string) ([]*AttestationRecord, error) {
	records := []*AttestationRecord{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	if user != "" {
		session = session.And("user = ?", user)
	}
	if sortField == "" || sortOrder == "" {
		session = session.Desc("id")
	}
	err := session.Find(&records)
	if err != nil {
		return records, err
	}
	return records, nil
}

func AddAttestationRecord(record *AttestationRecord) (bool, error) {
	if record.Name == "" {
		record.Name = util.GenerateId()
	}
	if record.CreatedTime == "" {
		record.CreatedTime = util.GetCurrentTime()
	}
	record.UpdatedTime = util.GetCurrentTime()
	if record.VerifiedTime == "" {
		record.VerifiedTime = record.UpdatedTime
	}

	affected, err := ormer.Engine.Insert(record)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}
