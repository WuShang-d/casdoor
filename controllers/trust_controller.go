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

package controllers

import (
	"encoding/json"
	"strings"

	"github.com/beego/beego/v2/server/web/pagination"
	"github.com/casdoor/casdoor/object"
	trustservice "github.com/casdoor/casdoor/service"
	"github.com/casdoor/casdoor/util"
)

// InitTrustSession
// @Title InitTrustSession
// @Tag Trust API
// @Description initialize a remote-attestation trust session without changing the Casdoor login flow
// @Param   body    body   service.TrustRequest  true        "The trust session request"
// @Success 200 {object} controllers.Response The Response object
// @router /init-trust-session [post]
func (c *ApiController) InitTrustSession() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	req, ok := c.readTrustRequest()
	if !ok {
		return
	}

	status, trustErr, err := trustservice.InitTrustSession(user, req)
	c.respondTrustStatus(status, trustErr, err)
}

// VerifyAttestation
// @Title VerifyAttestation
// @Tag Trust API
// @Description verify remote attestation evidence and update the trust session
// @Param   body    body   service.TrustRequest  true        "The attestation evidence"
// @Success 200 {object} controllers.Response The Response object
// @router /verify-attestation [post]
func (c *ApiController) VerifyAttestation() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	req, ok := c.readTrustRequest()
	if !ok {
		return
	}

	status, trustErr, err := trustservice.VerifyTrustSession(user, req)
	c.respondTrustStatus(status, trustErr, err)
}

// RefreshTrustSession
// @Title RefreshTrustSession
// @Tag Trust API
// @Description refresh an existing trust session with new attestation evidence
// @Param   body    body   service.TrustRequest  true        "The trust refresh request"
// @Success 200 {object} controllers.Response The Response object
// @router /refresh-trust-session [post]
func (c *ApiController) RefreshTrustSession() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	req, ok := c.readTrustRequest()
	if !ok {
		return
	}

	status, trustErr, err := trustservice.RefreshTrustSession(user, req)
	c.respondTrustStatus(status, trustErr, err)
}

// GetTrustStatus
// @Title GetTrustStatus
// @Tag Trust API
// @Description get the latest trust status for the current user
// @Success 200 {object} controllers.Response The Response object
// @router /get-trust-status [get]
func (c *ApiController) GetTrustStatus() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	status, trustErr, err := trustservice.GetTrustStatus(
		user,
		c.Ctx.Input.Query("owner"),
		c.Ctx.Input.Query("service"),
		c.Ctx.Input.Query("sessionId"),
	)
	c.respondTrustStatus(status, trustErr, err)
}

// GetAttestationRecords
// @Title GetAttestationRecords
// @Tag Trust API
// @Description get attestation records
// @Success 200 {object} controllers.Response The Response object
// @router /get-attestation-records [get]
func (c *ApiController) GetAttestationRecords() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	owner := c.Ctx.Input.Query("owner")
	if owner == "admin" || owner == "All" {
		owner = ""
	}
	if !c.IsGlobalAdmin() {
		owner = user.Owner
	}

	userFilter := ""
	if !c.IsAdmin() {
		userFilter = util.GetId(user.Owner, user.Name)
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		records, err := object.GetAttestationRecords(owner, userFilter)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(records)
		return
	}

	limitInt := util.ParseInt(limit)
	count, err := object.GetAttestationRecordCount(owner, userFilter, field, value)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limitInt, count)
	records, err := object.GetPaginationAttestationRecords(owner, userFilter, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(records, paginator.Nums())
}

// GetProtectedServices
// @Title GetProtectedServices
// @Tag Trust API
// @Description get protected AI services
// @Success 200 {object} controllers.Response The Response object
// @router /get-protected-services [get]
func (c *ApiController) GetProtectedServices() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	owner := c.Ctx.Input.Query("owner")
	if owner == "" {
		owner = user.Owner
	}
	if owner == "admin" || owner == "All" {
		owner = ""
	}
	if !c.IsGlobalAdmin() && owner == "" {
		owner = user.Owner
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		services, err := object.GetProtectedServices(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(services)
		return
	}

	limitInt := util.ParseInt(limit)
	count, err := object.GetProtectedServiceCount(owner, field, value)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limitInt, count)
	services, err := object.GetPaginationProtectedServices(owner, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(services, paginator.Nums())
}

// GetTrustPolicies
// @Title GetTrustPolicies
// @Tag Trust API
// @Description get trust policies
// @Success 200 {object} controllers.Response The Response object
// @router /get-trust-policies [get]
func (c *ApiController) GetTrustPolicies() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	owner := c.Ctx.Input.Query("owner")
	if owner == "" {
		owner = user.Owner
	}
	if owner == "admin" || owner == "All" {
		owner = ""
	}
	if !c.IsGlobalAdmin() && owner == "" {
		owner = user.Owner
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		policies, err := object.GetTrustPolicies(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(policies)
		return
	}

	limitInt := util.ParseInt(limit)
	count, err := object.GetTrustPolicyCount(owner, field, value)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limitInt, count)
	policies, err := object.GetPaginationTrustPolicies(owner, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(policies, paginator.Nums())
}

// UpdateTrustPolicy
// @Title UpdateTrustPolicy
// @Tag Trust API
// @Description update or add a risk-aware trust policy
// @Param   id     query    string  false       "The id ( owner/name ) of the trust policy"
// @Param   body    body   object.TrustPolicy  true        "The details of the trust policy"
// @Success 200 {object} controllers.Response The Response object
// @router /update-trust-policy [post]
func (c *ApiController) UpdateTrustPolicy() {
	owner, ok := c.RequireAdmin()
	if !ok {
		return
	}

	var policy object.TrustPolicy
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &policy)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if policy.Owner == "" {
		if owner == "" {
			policy.Owner = "built-in"
		} else {
			policy.Owner = owner
		}
	}
	if policy.Name == "" {
		policy.Name = object.DefaultTrustPolicyName
	}

	id := c.Ctx.Input.Query("id")
	if id == "" {
		id = policy.GetId()
	}

	oldPolicy, err := object.GetTrustPolicy(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if oldPolicy == nil {
		c.Data["json"] = wrapActionResponse(object.AddTrustPolicy(&policy))
	} else {
		c.Data["json"] = wrapActionResponse(object.UpdateTrustPolicy(id, &policy))
	}
	c.ServeJSON()
}

// ProxyProtectedAiService
// @Title ProxyProtectedAiService
// @Tag Trust API
// @Description Trust Gateway endpoint that checks Casdoor JWT, trust session and freshness before proxying AI requests
// @Param   body    body   service.TrustRequest  true        "The protected AI proxy request"
// @Success 200 {object} controllers.Response The Response object
// @router /proxy-ai-service [post]
func (c *ApiController) ProxyProtectedAiService() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	req, ok := c.readTrustRequest()
	if !ok {
		return
	}

	accessToken := c.getBearerToken()
	if accessToken == "" {
		accessToken = c.GetSessionToken()
	}

	result, trustErr, err := trustservice.ProxyProtectedAiService(user, accessToken, req)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if trustErr != nil {
		c.Data["json"] = &Response{Status: "error", Msg: trustErr.Code, Data: trustErr}
		c.ServeJSON()
		return
	}

	c.ResponseOk(result)
}

func (c *ApiController) readTrustRequest() (*trustservice.TrustRequest, bool) {
	req := &trustservice.TrustRequest{}
	if len(c.Ctx.Input.RequestBody) == 0 {
		return req, true
	}

	err := json.Unmarshal(c.Ctx.Input.RequestBody, req)
	if err != nil {
		c.ResponseError(err.Error())
		return nil, false
	}
	return req, true
}

func (c *ApiController) respondTrustStatus(status *trustservice.TrustStatus, trustErr *trustservice.TrustError, err error) {
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if trustErr != nil {
		c.Data["json"] = &Response{Status: "error", Msg: trustErr.Code, Data: status}
		c.ServeJSON()
		return
	}
	c.ResponseOk(status)
}

func (c *ApiController) getBearerToken() string {
	header := c.Ctx.Input.Header("Authorization")
	tokens := strings.Split(header, " ")
	if len(tokens) != 2 || tokens[0] != "Bearer" {
		return ""
	}
	return tokens[1]
}
