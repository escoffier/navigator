import { FormattedMessage, formatMessage } from "umi-plugin-react/locale";
import React, { Component, Fragment } from "react";
import { List, Descriptions, Form, Badge, Button } from "antd";

class SecurityView extends Component {
  render() {
    return (
      <Fragment>
        <Descriptions bordered>
          <Descriptions.Item label="威胁情报URL">
            intel.tensorsecurity.io/feed
          </Descriptions.Item>
          <Descriptions.Item label="威胁情报Token" span={2}>
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
          </Descriptions.Item>
          <Descriptions.Item label="病毒库版本">1.0.0</Descriptions.Item>
          <Descriptions.Item label="病毒库上次更新" span={2}>
            2019-10-24 18:00:00
          </Descriptions.Item>
          <Descriptions.Item label="恶意网络实体库版本">
            1.0.0
          </Descriptions.Item>
          <Descriptions.Item label="恶意网络实体库上次更新" span={2}>
            2019-10-24 18:00:00
          </Descriptions.Item>
          <Descriptions.Item label="隐私模式库版本">1.0.0</Descriptions.Item>
          <Descriptions.Item label="隐私模式库上次更新" span={2}>
            2019-10-24 18:00:00
          </Descriptions.Item>
          <Descriptions.Item label="下次情报库更新" span={2}>
            2019-11-01 18:00:00
          </Descriptions.Item>
        </Descriptions>
        <Form>
          <Form.Item>
            <Button type="primary"> 手动更新 </Button>
          </Form.Item>
        </Form>
      </Fragment>
    );
  }
}

export default SecurityView;
