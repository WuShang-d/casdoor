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
import {Switch, Table, Tooltip} from "antd";
import BaseListPage from "./BaseListPage";
import * as Setting from "./Setting";
import * as TrustBackend from "./backend/TrustBackend";

class ProtectedServicesPage extends BaseListPage {
  fetch = (params = {}) => {
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (!params.pagination) {
      params.pagination = {current: 1, pageSize: 10};
    }

    this.setState({loading: true});
    TrustBackend.getProtectedServices(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
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

  renderTable(services) {
    const columns = [
      {title: "Name", dataIndex: "name", key: "name", width: "180px", sorter: true, ...this.getColumnSearchProps("name")},
      {title: "Owner", dataIndex: "owner", key: "owner", width: "120px", sorter: true, ...this.getColumnSearchProps("owner")},
      {title: "Display name", dataIndex: "displayName", key: "displayName", width: "220px", sorter: true, ...this.getColumnSearchProps("displayName")},
      {title: "Model ID", dataIndex: "modelId", key: "modelId", width: "180px", sorter: true, ...this.getColumnSearchProps("modelId")},
      {
        title: "Endpoint",
        dataIndex: "endpoint",
        key: "endpoint",
        width: "260px",
        sorter: true,
        ...this.getColumnSearchProps("endpoint", (row, highlightContent) => (
          <Tooltip title={row.text || "mock gateway response"}>
            {row.text ? highlightContent : "mock gateway response"}
          </Tooltip>
        )),
      },
      {title: "Trust policy", dataIndex: "trustPolicy", key: "trustPolicy", width: "180px", sorter: true, ...this.getColumnSearchProps("trustPolicy")},
      {
        title: "Expected env_hash",
        dataIndex: "expectedEnvHash",
        key: "expectedEnvHash",
        width: "260px",
        ellipsis: {showTitle: false},
        render: (text) => <Tooltip title={text || "accept verifier env_hash"}>{text || "accept verifier env_hash"}</Tooltip>,
      },
      {
        title: "Enabled",
        dataIndex: "isEnabled",
        key: "isEnabled",
        width: "100px",
        render: (text) => <Switch disabled checked={text} />,
      },
    ];

    return (
      <Table
        scroll={{x: "100%"}}
        columns={columns}
        dataSource={services}
        rowKey={record => `${record.owner}/${record.name}`}
        size="middle"
        bordered
        title={() => "Protected AI Services"}
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
    );
  }
}

export default ProtectedServicesPage;
