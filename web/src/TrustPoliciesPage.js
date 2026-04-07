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

import React from "react";
import {Button, Drawer, Form, Input, InputNumber, Space, Switch, Table} from "antd";
import BaseListPage from "./BaseListPage";
import * as Setting from "./Setting";
import * as TrustBackend from "./backend/TrustBackend";

class TrustPoliciesPage extends BaseListPage {
  fetch = (params = {}) => {
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (!params.pagination) {
      params.pagination = {current: 1, pageSize: 10};
    }

    this.setState({loading: true});
    TrustBackend.getTrustPolicies(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      .then((res) => {
        this.setState({loading: false});
        if (res.status === "ok") {
          this.setState({
            data: res.data,
            pagination: {...params.pagination, total: res.data2},
            searchText: params.searchText,
            searchedColumn: params.searchedColumn,
          });
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  };

  setEditingField(field, value) {
    this.setState({
      editingPolicy: {
        ...this.state.editingPolicy,
        [field]: value,
      },
    });
  }

  savePolicy = () => {
    const policy = this.state.editingPolicy;
    TrustBackend.updateTrustPolicy(policy.owner, policy.name, policy)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", "Successfully saved");
          this.setState({editingPolicy: null});
          this.fetch({pagination: this.state.pagination});
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  };

  renderPolicyDrawer() {
    const policy = this.state.editingPolicy;
    if (!policy) {
      return null;
    }

    const numberStyle = {width: "100%"};
    return (
      <Drawer
        title={`Edit policy: ${policy.name}`}
        width={Setting.isMobile() ? "100%" : 620}
        open={!!policy}
        onClose={() => this.setState({editingPolicy: null})}
        extra={<Button type="primary" onClick={this.savePolicy}>Save</Button>}
      >
        <Form layout="vertical">
          <Form.Item label="Display name">
            <Input value={policy.displayName} onChange={e => this.setEditingField("displayName", e.target.value)} />
          </Form.Item>
          <Form.Item label="Description">
            <Input.TextArea value={policy.description} onChange={e => this.setEditingField("description", e.target.value)} />
          </Form.Item>
          <Form.Item label="Service">
            <Input value={policy.service} onChange={e => this.setEditingField("service", e.target.value)} />
          </Form.Item>
          <Form.Item label="Verifier URL">
            <Input placeholder="Empty means mock verifier" value={policy.verifierUrl} onChange={e => this.setEditingField("verifierUrl", e.target.value)} />
          </Form.Item>
          <Space style={{width: "100%"}} size="large">
            <Form.Item label="Max freshness seconds">
              <InputNumber style={numberStyle} value={policy.maxFreshnessSeconds} min={1} onChange={value => this.setEditingField("maxFreshnessSeconds", value)} />
            </Form.Item>
            <Form.Item label="Refresh interval seconds">
              <InputNumber style={numberStyle} value={policy.refreshIntervalSeconds} min={1} onChange={value => this.setEditingField("refreshIntervalSeconds", value)} />
            </Form.Item>
          </Space>
          <Space style={{width: "100%"}} size="large">
            <Form.Item label="Allow threshold">
              <InputNumber style={numberStyle} value={policy.allowRiskThreshold} min={0} max={1} step={0.01} onChange={value => this.setEditingField("allowRiskThreshold", value)} />
            </Form.Item>
            <Form.Item label="StepUp threshold">
              <InputNumber style={numberStyle} value={policy.stepUpRiskThreshold} min={0} max={1} step={0.01} onChange={value => this.setEditingField("stepUpRiskThreshold", value)} />
            </Form.Item>
          </Space>
          <Space style={{width: "100%"}} size="large">
            <Form.Item label="Data sensitivity">
              <InputNumber style={numberStyle} value={policy.dataSensitivity} min={0} max={1} step={0.01} onChange={value => this.setEditingField("dataSensitivity", value)} />
            </Form.Item>
            <Form.Item label="Context risk">
              <InputNumber style={numberStyle} value={policy.contextRisk} min={0} max={1} step={0.01} onChange={value => this.setEditingField("contextRisk", value)} />
            </Form.Item>
          </Space>
          <Form.Item label="Enabled">
            <Switch checked={policy.isEnabled} onChange={checked => this.setEditingField("isEnabled", checked)} />
          </Form.Item>
        </Form>
      </Drawer>
    );
  }

  renderTable(policies) {
    const columns = [
      {title: "Name", dataIndex: "name", key: "name", width: "190px", sorter: true, ...this.getColumnSearchProps("name")},
      {title: "Owner", dataIndex: "owner", key: "owner", width: "120px", sorter: true, ...this.getColumnSearchProps("owner")},
      {title: "Service", dataIndex: "service", key: "service", width: "180px", sorter: true, ...this.getColumnSearchProps("service")},
      {title: "Refresh", dataIndex: "refreshIntervalSeconds", key: "refreshIntervalSeconds", width: "110px", sorter: true, render: text => `${text}s`},
      {title: "Max freshness", dataIndex: "maxFreshnessSeconds", key: "maxFreshnessSeconds", width: "140px", sorter: true, render: text => `${text}s`},
      {title: "Allow threshold", dataIndex: "allowRiskThreshold", key: "allowRiskThreshold", width: "140px", sorter: true},
      {title: "StepUp threshold", dataIndex: "stepUpRiskThreshold", key: "stepUpRiskThreshold", width: "150px", sorter: true},
      {title: "Verifier URL", dataIndex: "verifierUrl", key: "verifierUrl", width: "240px", sorter: true, render: text => text || "mock verifier"},
      {title: "Enabled", dataIndex: "isEnabled", key: "isEnabled", width: "100px", render: text => <Switch disabled checked={text} />},
      {
        title: "Action",
        key: "action",
        width: "100px",
        fixed: "right",
        render: (_, record) => <Button type="link" onClick={() => this.setState({editingPolicy: Setting.deepCopy(record)})}>Edit</Button>,
      },
    ];

    return (
      <div>
        <Table
          scroll={{x: "100%"}}
          columns={columns}
          dataSource={policies}
          rowKey={record => `${record.owner}/${record.name}`}
          size="middle"
          bordered
          title={() => "Trust Policies"}
          loading={this.state.loading}
          pagination={{
            total: this.state.pagination.total,
            pageSize: this.state.pagination.pageSize,
            showQuickJumper: true,
            showSizeChanger: true,
            showTotal: () => `${this.state.pagination.total} in total`,
          }}
          onChange={this.handleTableChange}
        />
        {this.renderPolicyDrawer()}
      </div>
    );
  }
}

export default TrustPoliciesPage;
