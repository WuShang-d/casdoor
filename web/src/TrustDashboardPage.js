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
import {Alert, Button, Card, Col, Descriptions, Row, Select, Space, Spin, Statistic, Tag} from "antd";
import * as Setting from "./Setting";
import * as TrustBackend from "./backend/TrustBackend";

/* eslint-disable react-hooks/exhaustive-deps */

const defaultServiceName = "ai-inference-default";

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

function getMockLayers(modelId) {
  return [
    {name: "code", hash: "casdoor-ai-portal-code-v1"},
    {name: "model", hash: modelId || "casdoor-demo-llm-v1"},
    {name: "runtime", hash: "go-trust-orchestrator-v1"},
    {name: "config", hash: "refresh=120"},
  ];
}

function TrustDashboardPage(props) {
  const [services, setServices] = React.useState([]);
  const [serviceName, setServiceName] = React.useState(defaultServiceName);
  const [trustStatus, setTrustStatus] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [gatewayLoading, setGatewayLoading] = React.useState(false);
  const [gatewayResult, setGatewayResult] = React.useState(null);
  const [countdown, setCountdown] = React.useState(0);
  const autoStarted = React.useRef(false);

  React.useEffect(() => {
    loadServices();
  }, []);

  React.useEffect(() => {
    const timer = setInterval(() => {
      const nextRefreshTime = trustStatus?.session?.nextRefreshTime;
      if (!nextRefreshTime) {
        setCountdown(0);
        return;
      }
      setCountdown(Math.max(0, Math.ceil((new Date(nextRefreshTime).getTime() - Date.now()) / 1000)));
    }, 1000);
    return () => clearInterval(timer);
  }, [trustStatus]);

  const owner = props.account?.owner || "built-in";

  const loadServices = () => {
    TrustBackend.getProtectedServices(owner)
      .then((res) => {
        if (res.status !== "ok") {
          Setting.showMessage("error", res.msg);
          return;
        }
        const data = res.data || [];
        setServices(data);
        if (data.length > 0) {
          setServiceName(data[0].name);
        }
      });
  };

  const getSelectedService = () => {
    return services.find(service => service.name === serviceName);
  };

  const buildBaseRequest = (session = null) => {
    const selectedService = getSelectedService();
    return {
      owner: session?.owner || selectedService?.owner || owner,
      service: selectedService?.name || serviceName || defaultServiceName,
      modelId: selectedService?.modelId || trustStatus?.modelId || "casdoor-demo-llm-v1",
    };
  };

  const applyStatusResponse = (res) => {
    if (res.data) {
      setTrustStatus(res.data);
    }
    if (res.status === "error") {
      Setting.showMessage("warning", res.msg);
    }
  };

  const initAndVerify = () => {
    setLoading(true);
    setGatewayResult(null);
    const initReq = buildBaseRequest();
    TrustBackend.initTrustSession(initReq)
      .then((initRes) => {
        if (initRes.status !== "ok") {
          applyStatusResponse(initRes);
          return null;
        }
        const session = initRes.data?.session;
        const verifyReq = {
          ...initReq,
          owner: session?.owner || initReq.owner,
          sessionId: session?.name,
          timestamp: new Date().toISOString(),
          nonce: `mock-${Date.now()}`,
          evidence: "mock-verifier",
          layers: getMockLayers(initReq.modelId),
        };
        return TrustBackend.verifyAttestation(verifyReq);
      })
      .then((verifyRes) => {
        if (!verifyRes) {
          return;
        }
        applyStatusResponse(verifyRes);
      })
      .catch(error => Setting.showMessage("error", `${error}`))
      .finally(() => setLoading(false));
  };

  const refreshSession = () => {
    const session = trustStatus?.session;
    if (!session) {
      initAndVerify();
      return;
    }

    setLoading(true);
    const refreshReq = {
      ...buildBaseRequest(session),
      sessionId: session.name,
      timestamp: new Date().toISOString(),
      nonce: `refresh-${Date.now()}`,
      evidence: "mock-verifier-refresh",
      layers: getMockLayers(session.modelId),
    };
    TrustBackend.refreshTrustSession(refreshReq)
      .then(applyStatusResponse)
      .catch(error => Setting.showMessage("error", `${error}`))
      .finally(() => setLoading(false));
  };

  const testGateway = () => {
    const session = trustStatus?.session;
    if (!session) {
      Setting.showMessage("warning", "Please initialize a trust session first");
      return;
    }

    setGatewayLoading(true);
    TrustBackend.proxyAiService({
      ...buildBaseRequest(session),
      sessionId: session.name,
      assertion: session.assertion,
      payload: {
        prompt: "hello from Casdoor Trust Gateway",
      },
    })
      .then((res) => {
        setGatewayResult(res);
        if (res.status === "ok") {
          Setting.showMessage("success", "Trust Gateway allowed the AI request");
        } else {
          Setting.showMessage("error", res.msg);
        }
      })
      .catch(error => Setting.showMessage("error", `${error}`))
      .finally(() => setGatewayLoading(false));
  };

  React.useEffect(() => {
    if (autoStarted.current) {
      return;
    }
    autoStarted.current = true;
    initAndVerify();
  }, []);

  const session = trustStatus?.session || {};

  return (
    <div>
      <Space direction="vertical" size="large" style={{width: "100%"}}>
        <Alert
          type="info"
          showIcon
          message="Joint Authentication Trust Dashboard"
          description="Casdoor keeps the original login and token issuance flow. The remote-attestation result is represented as an independent trust session / trust assertion."
        />
        <Card
          title="Trust Orchestrator"
          extra={
            <Space>
              <Select
                style={{width: 260}}
                value={serviceName}
                onChange={setServiceName}
                options={(services.length === 0 ? [{name: defaultServiceName, displayName: "Default Protected AI Inference"}] : services).map(service => ({
                  value: service.name,
                  label: `${service.displayName || service.name}`,
                }))}
              />
              <Button type="primary" onClick={initAndVerify} loading={loading}>Init + Verify</Button>
              <Button onClick={refreshSession} loading={loading}>Refresh</Button>
              <Button onClick={testGateway} loading={gatewayLoading}>Gateway Test</Button>
            </Space>
          }
        >
          {loading && !trustStatus ? (
            <Spin />
          ) : (
            <Space direction="vertical" size="large" style={{width: "100%"}}>
              <Row gutter={16}>
                <Col span={6}><Statistic title="Freshness age" value={session.freshnessAgeSeconds || 0} suffix="s" /></Col>
                <Col span={6}><Statistic title="Risk score" value={session.riskScore || 0} precision={4} /></Col>
                <Col span={6}><Statistic title="Next refresh" value={countdown} suffix="s" /></Col>
                <Col span={6}><Statistic title="Refresh policy" value={session.refreshIntervalSeconds || 120} suffix="s" /></Col>
              </Row>
              <Descriptions bordered column={1} size="small">
                <Descriptions.Item label="current user">{trustStatus?.currentUser || `${props.account?.owner}/${props.account?.name}`}</Descriptions.Item>
                <Descriptions.Item label="target protected service">{trustStatus?.targetService || serviceName}</Descriptions.Item>
                <Descriptions.Item label="model id">{trustStatus?.modelId || session.modelId || getSelectedService()?.modelId || "casdoor-demo-llm-v1"}</Descriptions.Item>
                <Descriptions.Item label="attestation status">{session.attestationStatus || "not initialized"}</Descriptions.Item>
                <Descriptions.Item label="env_hash">{session.envHash || "-"}</Descriptions.Item>
                <Descriptions.Item label="cbt_digest">{session.cbtDigest || "-"}</Descriptions.Item>
                <Descriptions.Item label="freshness age">{session.freshnessAgeSeconds ?? "-"} s</Descriptions.Item>
                <Descriptions.Item label="risk_score">{session.riskScore ?? "-"}</Descriptions.Item>
                <Descriptions.Item label="final decision">
                  <Tag color={getDecisionColor(session.decision)}>{session.decision || "Pending"}</Tag>
                  {session.errorCode ? <Tag color="red">{session.errorCode}</Tag> : null}
                </Descriptions.Item>
                <Descriptions.Item label="next refresh countdown">{countdown} s</Descriptions.Item>
                <Descriptions.Item label="latest verification timestamp">{session.lastVerifiedTime || "-"}</Descriptions.Item>
                <Descriptions.Item label="trust assertion">{session.assertion || "-"}</Descriptions.Item>
              </Descriptions>
            </Space>
          )}
        </Card>
        {gatewayResult ? (
          <Card title="Trust Gateway Result">
            <pre style={{whiteSpace: "pre-wrap", margin: 0}}>{JSON.stringify(gatewayResult, null, 2)}</pre>
          </Card>
        ) : null}
      </Space>
    </div>
  );
}

export default TrustDashboardPage;
