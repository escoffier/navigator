// import { Card, Col, Form, List, Row, Select, Typography } from 'antd';
import {
  Form,
  Select,
  Result,
  InputNumber,
  Switch,
  Radio,
  Slider,
  Button,
  Upload,
  Icon,
  Rate,
  Checkbox,
  Row,
  Col,
  Tag,
  Input,
  Modal
} from 'antd';

import React, { Component } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';

const { TextArea } = Input;

const defaultConfig = `
  apiVersion: v1
  clusters:
  - cluster:
      certificate-authority-data: DATA+OMITTED
      server: https://127.0.0.1:16443
    name: microk8s-cluster
  contexts:
  - context:
      cluster: microk8s-cluster
      user: admin
    name: microk8s
  current-context: microk8s
  kind: Config
  preferences: {}
  users:
  - name: admin
    user:
      password: MnlkN0RJSkFkTmp4N0pVNDVQK3UrZG82STg1OW5abVRTL2V2a2VxVUVaWT0K
      username: admin
`

@connect(({ configClusterCreate: { rule, validated, message}, assetsAndclusters }) => ({
  rule,
  validated,
  message,
  assetsAndclusters,
}))
class ClusterCreateDetail extends Component {
    state = {
      rule: {},
      inputVisible: false,
      visible: false,
      choices: [],
      validate: false
    };

    handleSubmit = e => {
      e.preventDefault();
      const { dispatch } = this.props;

      this.props.form.validateFields((err, values) => {
        if (!err) {
          console.log('Received values of form: ', values);
        }

        values.config = btoa(values.kubectlconfig);
        delete values.kubectlconfig

        dispatch({
          type: 'configClusterCreate/create',
          payload: values,
        });
      });
    };

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    handleOk() {
      const { dispatch } = this.props;
      dispatch({
        type: 'configClusterCreate/clear',
      });

      this.props.history.push("/settings/agent");
    }

    render() {
      const { getFieldDecorator } = this.props.form;
      const { assetsAndclusters: { data } } = this.props;
      const handleClick = this.handleClick.bind(this);
      const handleOk = this.handleOk.bind(this);
      const { validated, message } = this.props;

      const content = <Result
          status="success"
          title="成功创建"
          subTitle={message}
      />

      const formItemLayout = {
        labelCol: { span: 6 },
        wrapperCol: { span: 14 },
      };

      const { query } = this.props.location;
      const items = query.items || [];
      let tags = [];


      items.forEach((item, i) => {
        if (data.list && data.list[parseInt(item)]) {
          tags.push({
            key: item,
            name: data.list[parseInt(item)].name,
          })
        }
      });

      return (
      <div>
      <Form {...formItemLayout} onSubmit={this.handleSubmit}>
        <Form.Item label="集群名称">
          {getFieldDecorator('name', {
            rules: [
              {
                required: true,
                message: '请输入集群名称!',
              },
            ],
          })(<Input />)}
        </Form.Item>
        <Form.Item label="选择规则类型" hasFeedback>
          {getFieldDecorator('type', {
            rules: [{ required: true, message: '请选择集群类型' }],
          })(
            <Select placeholder="选择集群类型">
              <Select.Option value={3}>Kubernetes</Select.Option>
              <Select.Option value={0}>Openshift</Select.Option>
            </Select>,
          )}
        </Form.Item>
        <Form.Item label="粘贴配置yaml" hasFeedback>
          {getFieldDecorator('kubectlconfig', {
          })(
              <TextArea rows={25} placeholder={defaultConfig}/>
          )}
        </Form.Item>
        {/*<Form.Item label="链接测试">*/}
          {/*<Button onClick={handleVerify}>*/}
              {/*连接认证*/}
          {/*</Button>*/}
        {/*</Form.Item>*/}
        {/*<Form.Item label="选择Service 账号">*/}
          {/*{getFieldDecorator('serviceaccounts')(*/}
            {/*<Select placeholder="选择集群类型">*/}
              {/*{selects}*/}
            {/*</Select>,*/}
          {/*)}*/}
        {/*</Form.Item>*/}
        <Form.Item wrapperCol={{ span: 12, offset: 6 }}>
          <Button type="primary" htmlType="submit">
            递交
          </Button>
          <Button onClick={handleClick}>
            取消
          </Button>
        </Form.Item>
      </Form>
        <Modal
          title="确认"
          visible={validated}
          onOk={handleOk}
        >
          {content? content: <p>{'确认递交?'}</p>}
        </Modal>
      </div>
      );
    }
}

export default Form.create()(ClusterCreateDetail);
