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

const DefaultProtectedServiceName = "ai-inference-default"

type ProtectedService struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"varchar(500)" json:"description"`

	ModelId         string `xorm:"varchar(200)" json:"modelId"`
	Endpoint        string `xorm:"varchar(500)" json:"endpoint"`
	TrustPolicy     string `xorm:"varchar(100)" json:"trustPolicy"`
	ExpectedEnvHash string `xorm:"varchar(128)" json:"expectedEnvHash"`
	IsEnabled       bool   `json:"isEnabled"`

	PolicyObj *TrustPolicy `xorm:"-" json:"policyObj,omitempty"`
}

func GetProtectedServiceCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&ProtectedService{})
}

func GetProtectedServices(owner string) ([]*ProtectedService, error) {
	services := []*ProtectedService{}
	err := ormer.Engine.Desc("created_time").Find(&services, &ProtectedService{Owner: owner})
	if err != nil {
		return services, err
	}

	err = extendProtectedServicesWithPolicy(services)
	if err != nil {
		return services, err
	}
	return services, nil
}

func GetPaginationProtectedServices(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*ProtectedService, error) {
	services := []*ProtectedService{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&services)
	if err != nil {
		return services, err
	}

	err = extendProtectedServicesWithPolicy(services)
	if err != nil {
		return services, err
	}
	return services, nil
}

func getProtectedService(owner string, name string) (*ProtectedService, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	service := ProtectedService{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&service)
	if err != nil {
		return nil, err
	}

	if !existed {
		return nil, nil
	}

	err = extendProtectedServiceWithPolicy(&service)
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func GetProtectedService(id string) (*ProtectedService, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getProtectedService(owner, name)
}

func GetProtectedServiceByName(owner string, name string) (*ProtectedService, error) {
	return getProtectedService(owner, name)
}

func AddProtectedService(service *ProtectedService) (bool, error) {
	if service.CreatedTime == "" {
		service.CreatedTime = util.GetCurrentTime()
	}
	service.UpdatedTime = util.GetCurrentTime()
	if service.TrustPolicy == "" {
		service.TrustPolicy = DefaultTrustPolicyName
	}

	affected, err := ormer.Engine.Insert(service)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func UpdateProtectedService(id string, service *ProtectedService) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	oldService, err := getProtectedService(owner, name)
	if err != nil {
		return false, err
	}
	if oldService == nil {
		return false, nil
	}
	if service.CreatedTime == "" {
		service.CreatedTime = oldService.CreatedTime
	}
	service.UpdatedTime = util.GetCurrentTime()

	affected, err := ormer.Engine.ID(core.PK{owner, name}).AllCols().Update(service)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func DeleteProtectedService(service *ProtectedService) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{service.Owner, service.Name}).Delete(&ProtectedService{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func (service *ProtectedService) GetId() string {
	return fmt.Sprintf("%s/%s", service.Owner, service.Name)
}

func extendProtectedServicesWithPolicy(services []*ProtectedService) error {
	for _, service := range services {
		err := extendProtectedServiceWithPolicy(service)
		if err != nil {
			return err
		}
	}
	return nil
}

func extendProtectedServiceWithPolicy(service *ProtectedService) error {
	if service == nil || service.TrustPolicy == "" {
		return nil
	}

	policy, err := GetTrustPolicyByName(service.Owner, service.TrustPolicy)
	if err != nil {
		return err
	}
	service.PolicyObj = policy
	return nil
}
