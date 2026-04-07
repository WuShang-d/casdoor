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
import {Table, Tag, Tooltip} from "antd";
import BaseListPage from "./BaseListPage";
import * as Setting from "./Setting";
import * as TrustBackend from "./backend/TrustBackend";

function getDecisionColor(decision) {
  if (decision === "Allow") {
    return "green";
  } else if (decision === "StepUp") {
    return "orange";
  } else if (decision === "Deny") {
    return "red";
  }
  return "blue";
}

class AttestationRecordsPage extends BaseListPage {
  UNSAFE_componentWillMount() {
    this.state.pagination.pageSize = 20;
    const {pagination} = this.state;
    this.fetch({pagination});
  }

  fetch = (params = {}) => {
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (!params.pagination) {
      params.pagination = {current: 1, pageSize: 20};
    }

    this.setState({loading: true});
    TrustBackend.getAttestationRecords(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
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

  renderTable(records) {
    const columns = [
      {title: "ID", dataIndex: "id", key: "id", width: "80px", sorter: true},
      {title: "Time", dataIndex: "createdTime", key: "createdTime", width: "170px", sorter: true, render: text => Setting.getFormattedDate(text)},
      {title: "Owner", dataIndex: "owner", key: "owner", width: "120px", sorter: true, ...this.getColumnSearchProps("owner")},
      {title: "User", dataIndex: "user", key: "user", width: "160px", sorter: true, ...this.getColumnSearchProps("user")},
      {title: "Service", dataIndex: "service", key: "service", width: "180px", sorter: true, ...this.getColumnSearchProps("service")},
      {title: "Model ID", dataIndex: "modelId", key: "modelId", width: "180px", sorter: true, ...this.getColumnSearchProps("modelId")},
      {title: "Status", dataIndex: "attestationStatus", key: "attestationStatus", width: "130px", sorter: true, render: text => <Tag color={text === "verified" ? "green" : "red"}>{text}</Tag>},
      {title: "Decision", dataIndex: "decision", key: "decision", width: "120px", sorter: true, render: text => <Tag color={getDecisionColor(text)}>{text}</Tag>},
      {title: "Freshness", dataIndex: "freshnessAgeSeconds", key: "freshnessAgeSeconds", width: "120px", sorter: true, render: text => `${text}s`},
      {title: "Risk score", dataIndex: "riskScore", key: "riskScore", width: "120px", sorter: true},
      {
        title: "env_hash",
        dataIndex: "envHash",
        key: "envHash",
        width: "260px",
        ellipsis: {showTitle: false},
        render: text => <Tooltip title={text}>{text}</Tooltip>,
      },
      {
        title: "cbt_digest",
        dataIndex: "cbtDigest",
        key: "cbtDigest",
        width: "260px",
        ellipsis: {showTitle: false},
        render: text => <Tooltip title={text}>{text}</Tooltip>,
      },
      {title: "Error code", dataIndex: "errorCode", key: "errorCode", width: "180px", sorter: true, ...this.getColumnSearchProps("errorCode")},
    ];

    return (
      <Table
        scroll={{x: "100%"}}
        columns={columns}
        dataSource={records}
        rowKey="id"
        size="middle"
        bordered
        title={() => "Attestation Records"}
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

export default AttestationRecordsPage;
