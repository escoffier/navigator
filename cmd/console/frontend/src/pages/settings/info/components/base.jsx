import { Button, Form, Input, Col, Row, Select, Upload, Descriptions, Badge, message } from 'antd';
import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import React, { Component, Fragment } from 'react';
import { GridContent } from '@ant-design/pro-layout';
import { connect } from 'dva';
import styles from './BaseView.less';


@connect(({ settingsAndinfo }) => ({
  currentUser: settingsAndinfo.currentUser,
}))
class BaseView extends Component {
  view = undefined;

  componentDidMount() {

  }

  render() {
    return (
      <Fragment>
      <Descriptions bordered>
      <Descriptions.Item label="系统版本">1.1.0</Descriptions.Item>
      <Descriptions.Item label="许可证所有者">南京尓嘉网络科技有限公司</Descriptions.Item>
      <Descriptions.Item label="许可证类型">企业</Descriptions.Item>
      <Descriptions.Item label="许可证起始日">2019-04-24 18:00:00</Descriptions.Item>
      <Descriptions.Item label="许可证终止日" span={2}>
        2029-04-24 18:00:00
      </Descriptions.Item>
      <Descriptions.Item label="许可证状态" span={3}>
        <Badge status="processing" text="运行中(剩余3650天)" />
      </Descriptions.Item>
      <Descriptions.Item label="负载统计（容器数）">35/2000</Descriptions.Item>
      <Descriptions.Item label="负载统计（主机数）">2/200</Descriptions.Item>
      </Descriptions>
        <Form>
          <Form.Item label="输入新证书">
            <Input lable="输入新证书"/>
          </Form.Item>
          <Form.Item>
            <Button type="primary"> 更新 </Button>
          </Form.Item>
        </Form>
      </Fragment>
    );
  }
}

export default Form.create()(BaseView);
