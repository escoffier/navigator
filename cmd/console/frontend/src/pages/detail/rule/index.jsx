// import { Card, Col, Form, List, Row, Select, Typography } from 'antd';
import {
  Form,
  Select,
  InputNumber,
  Switch,
  Radio,
  Slider,
  Button,
  Upload,
  Icon,
  Rate,
  Transfer,
  Checkbox,
  TreeSelect,
  Row,
  Col,
  Tag,
  Input,
  Modal
} from 'antd';

import React, { Component } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import styles from './style.less';


const { TreeNode } = TreeSelect;
const formItemLayout = {
  labelCol: { span: 6 },
  wrapperCol: { span: 14 },
};


function renderTreeSelect(arr) {
  return (
    <TreeSelect
      dropdownStyle={{ maxHeight: 400, overflow: 'auto' }}
      placeholder="请选择"
      allowClear
      multiple
      treeDefaultExpandAll>
      {arr.map((item, i) => {
        return (
          <TreeNode value={item.key} title={item.name} key={item.key}>
            {
              (item.nodes || []).map((node, i) => {
                return (<TreeNode value={node.key} title={node.name} key={node.key}/>)
              })
            }
          </TreeNode>
        )
      })}
    </TreeSelect>
  );
}

@connect(({ rule: { rule, formData }, assetsAndclusters }) => ({
  rule,
  formData,
  assetsAndclusters,
}))
class RuleCreateDetail extends Component {
    state = {
      category: null,
      rule: {},
      visible: false,
      action: 'add',
      targetKeys: [1, 2],
    };

    handleSubmit = e => {
      e.preventDefault();
      this.props.form.validateFields((err, values) => {
        if (!err) {
          console.log('Received values of form: ', values);
        }
      });
    };

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    handleCancel() {
      this.setState({
        visible: !this.state.visible,
      })
    }

    handleOk() {
      this.handleCancel();
      this.handleClick();
    }

    componentDidMount() {
      const { fillData } = this.props.location;
      const { action } = this.props.match.params || 'add';
      this.setState({
        ...fillData,
        action,
      });
      if (fillData && fillData.category) {
        this.handleFetchFormData(fillData.category || 'host');
      } else {
        this.handleFetchFormData('host');
      }
    }

    handleFetchFormData(cate) {
      const { dispatch } = this.props;
      console.log(cate);
      if (dispatch)
        dispatch({
          type: 'rule/fetch',
          payload: {
            cate: cate || 'host',
          },
        });
    }

    handleTransferChange = targetKeys => {
      this.setState({ targetKeys });
    };

    render() {
      const { getFieldDecorator } = this.props.form;
      const { assetsAndclusters: { data} } = this.props;
      const { formData } = this.props;
      const { visible, action, fillData} = this.state;
      const handleClick = this.handleClick.bind(this);
      const handleOk = this.handleOk.bind(this);
      const handleCancel = this.handleCancel.bind(this);
      const handleTransferChange = this.handleTransferChange.bind(this);
      const handleFetchFormData = this.handleFetchFormData.bind(this);
      const treeNode = formData.objs || [];

      const filterOption = (inputValue, option) => option.description.indexOf(inputValue) > -1;

      console.log(this.state);

      const addForm = <Form {...formItemLayout} onSubmit={this.handleSubmit}>
        <Form.Item label="名称">
          {getFieldDecorator('ruleName', {
            rules: [
              {
                required: true,
                message: '请输入规则名!',
              },
            ],
            initialValue: (this.state.ruleName) ? this.state.ruleName : '',
          })(<Input disabled={this.state.ruleName}/>)}
        </Form.Item>
        <Form.Item label="选择规则类型" hasFeedback>
          {getFieldDecorator('category', {
            rules: [{ required: true, message: '选择Policy类型!' }],
            initialValue: (this.state.category) ? this.state.category: 'host',
          })(
            <Select placeholder="选择策略类型" onChange={(value) => handleFetchFormData(value)}>
              <Select.Option value="host">主机监测</Select.Option>
              <Select.Option value="monitor">网络监测</Select.Option>
              <Select.Option value="dpi">入侵流量监测</Select.Option>
              <Select.Option value="image">镜像扫描</Select.Option>
              <Select.Option value="scap">合规监测</Select.Option>
            </Select>,
          )}
        </Form.Item>
        <Form.Item label="选择代理" hasFeedback>
          {getFieldDecorator('agent', {
            rules: [{ required: true, message: '选择Policy类型!' }],
            initialValue: (fillData && fillData.agent) ? fillData.agent: '0',
          })(
            <Select>
              {
                (formData.agents || []).map((item, i) => {
                  return (<Select.Option key={`option-${i}`} value={`${i}`}>{item}</Select.Option>)
                })
              }
            </Select>,
          )}
        </Form.Item>
        <Form.Item label="已选对象">
          {getFieldDecorator('objects', {
            initialValue: this.state.objects ? this.state.objects: [],
          })(
            renderTreeSelect(treeNode),
          )}
        </Form.Item>
        <Form.Item label="优先级">
          {getFieldDecorator('level', {
            initialValue: this.state.level ? this.state.level: 5,
          })(<InputNumber min={1} max={10} />)}
          <span className="ant-form-text"> 级（高数值表示高优先级，最高10）</span>
        </Form.Item>
        <Form.Item label="动作">
          {getFieldDecorator('alertAction', {
            initialValue: this.state.alertAction ? this.state.alertAction: 'b',
          })(
            <Radio.Group>
              <Radio.Button value="a">记录</Radio.Button>
              <Radio.Button value="b">告警</Radio.Button>
              <Radio.Button value="c">阻拦</Radio.Button>
            </Radio.Group>,
          )}
        </Form.Item>
        <Form.Item label="选择规则">
          {getFieldDecorator('rules')(
            <Transfer
              dataSource={formData.rules || []}
              titles={['可选', '已选中']}
              targetKeys={this.state.targetKeys}
              filterOption={filterOption}
              onChange={handleTransferChange}
              render={item => item.title}
            />,
          )}
        </Form.Item>


        <Form.Item wrapperCol={{ span: 12, offset: 6 }}>
          <Button type="primary" htmlType="submit" onClick={handleCancel}>
            递交
          </Button>
          <Button onClick={handleClick}>
            取消
          </Button>
        </Form.Item>
      </Form>;


      return (
      <div>
        {addForm}
        <Modal
          title="确认"
          visible={visible}
          onOk={handleOk}
          onCancel={handleCancel}
        >
          <p>{'确认递交?'}</p>
        </Modal>
      </div>
      );
    }
}

export default Form.create({
  onValuesChange({ dispatch }, changedValues, values) {
    // 表单项变化时请求数据
    // 模拟查询表单生效
    console.log(values);
  },
})(RuleCreateDetail);
