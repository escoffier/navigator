import { Button, Card, Col, Table, Checkbox, Switch, Form, Divider, Icon, Input, List, Row, Select, Tag, Modal } from 'antd';
import React, { Component, Fragment } from 'react';
import { connect } from 'dva';
import moment from 'moment';
import Link from 'umi/link';
import router from 'umi/router';
import styles from './style.less';
import EditabelTable from './components/EditabelTable';

import { GridContent } from '@ant-design/pro-layout';


const categories = [
  '主机监控',
  '网络监控',
  '流量监控',
  '镜像扫描',
  '合规审计',
];


class Rule extends Component {
  state = {
    visible: false,
    settingVisible: false,
    custom: [],
    selectedRow: null,
  };

  componentDidMount() {
    const { dispatch } = this.props;
    const { config } = this.state;
    dispatch({
      type: 'policyAndrules/fetch',
      payload: config,
    });
  }

  handleAddCustomRule() {
    this.setState({
      visible: true,
    })
  }

  handleModalOk() {
    const { form } = this.props;
    const { custom } = this.state;

    form.validateFields((err, fieldsValue) => {
      if (err) return;
      const values = {
        ...fieldsValue,
      };

      const defaultEntry = {name: 'input name:'};
      const columns = [{ title: '序号', dataIndex: 'key', key: 'key'}, { title: 'CVE号', dataIndex: 'name', key: 'name', editable: true}];

      const record = {
        key: 100,
        name: values.name || 'n/a',
        title: `自定义规则${values.name}` || 'n/a',
        chosen: false,
        agents: [parseInt(values.ruleType) % 5],
        customized: true,
        needConfig: true,
        config: {
          white: {data: {defaultEntry, columns, dataSource:[]}},
          black: {data: {defaultEntry, columns, dataSource:[]}},
        },
      };

      custom.push(record);
      this.setState({
        custom,
        visible: false,
      })
    })
  }

  handleModalCancel() {
    this.setState({
      visible: false,
      settingVisible: false,
    })
  }

  handleModalSettingOk() {
    this.setState({
      visible: false,
      settingVisible: false,
    })
  }

  handleShowModal(row) {
    this.setState({
      settingVisible: true,
      selectedRow: row,
    })
  }

  handleShowTable(data, title) {
    console.log(data);
    return (<Card title={title}><EditabelTable title data={data}/></Card>);
  }

  renderDefault() {
    const {
      form: { getFieldDecorator },
    } = this.props;
    const { settingVisible, selectedRow } = this.state;
    const handleModalSettingOk = this.handleModalSettingOk.bind(this);
    const handleModalCancel = this.handleModalCancel.bind(this);
    if (selectedRow) {
      if (selectedRow.config) {
        const config = selectedRow.config;
        return (
        <Modal title={`配置规则:${selectedRow.title}`}
            width={800}
            visible={settingVisible}
            onOk={handleModalSettingOk}
            onCancel={handleModalCancel}
        >
          <Form>
            <Form.Item label="设为全局默认(策略中将将自动选中)">
              {getFieldDecorator('enableGlobal',
                {initialValue: selectedRow.chosen},
              )(<Switch/>)
              }
            </Form.Item>
            {config.white? this.handleShowTable(config.white.data, '白名单'): <div></div>}
            {config.black? this.handleShowTable(config.black.data, '黑名单'): <div></div>}
            {config.file? this.handleShowTable(config.file.data, '白名单'): <div></div>}
          </Form>
        </Modal>)
      } else {
        return (
        <Modal title={`配置规则:${selectedRow.title}`}
            visible={settingVisible}
            onOk={handleModalSettingOk}
            onCancel={handleModalCancel}
        >
          <Form>
            <Form.Item label="设为全局默认(策略中将将自动选中)">
              {getFieldDecorator('enableGlobal', {initialValue: selectedRow.chosen},
              )
                (<Switch/>)
              }
            </Form.Item>
          </Form>
        </Modal>)
      }
    } else {
      return (<div/>)
    }
  }

  render() {
    const {
      form,
      policyAndrules: { list },
      loading,
    } = this.props;
    const { getFieldDecorator } = form;
    const { visible, custom } = this.state;
    const handleAddCustomRule = this.handleAddCustomRule.bind(this);
    const handleModalOk = this.handleModalOk.bind(this);
    const handleModalCancel = this.handleModalCancel.bind(this);
    const renderDefault = this.renderDefault.bind(this);
    const handleShowModal = this.handleShowModal.bind(this);
    const displayList = custom.concat(list);
    const columns = [
        {
          title: '规则名称',
          dataIndex: 'name',
        },
        {
          title: '支持策略类型',
          dataIndex: 'agents',
          align: 'right',
          render: (text, record) => ((record.agents || []).map(item => `${categories[item || 0]} `)),
        },
        {
          title: '是否为全局默认',
          render: (text, record) => (
            <Fragment>
              {
                record.chosen ? <Icon type="check-circle" theme="twoTone" twoToneColor="#52c41a" /> :
                  <Icon type="close-circle" theme="twoTone" twoToneColor="#c4231c"/>
              }
            </Fragment>
          ),
        },
        {
          title: '组别',
          render: (text, record) => (record.customized ? '用户自定义' : '系统默认'),
        },
        {
          title: '操作',
          render: (text, record) => (
            <Fragment>
              <a onClick={() => handleShowModal(record)}>设置</a>
            </Fragment>
          ),
        },
      ];

    return (
      <div>
        <Row>
            <Button type="link" icon="plus" block onClick={handleAddCustomRule}>
              添加自定义规则
            </Button>
        </Row>
        <Table
          bordered
          dataSource={displayList}
          columns={columns}
          expandedRowRender={record => <p style={{ margin: 0 }}>描述： {record.title}</p>}
          pagination={{
            style: {
              marginBottom: 0,
            },
            pageSize: 50,
          }}
        />
        <Modal
          title="添加新规则"
          visible={visible}
          onOk={() => handleModalOk()}
          onCancel={handleModalCancel}
        >
        <Form onSubmit={() => handleModalOk()}>
          <Form.Item label="输入规则名称">
            {getFieldDecorator('name', {
                rules: [{ required: true, message: '请选择自定义规则类型!' }],
              })(<Input lable="输入规则名称"/>)
            }
          </Form.Item>
            <Form.Item label="请选择自定义规则类型" hasFeedback>
              {getFieldDecorator('ruleType', {
                rules: [{ required: true, message: '请选择自定义规则类型!' }],
              })(
                <Select>
                  <Select.Option key="0" value="3">黑白名单漏洞检测</Select.Option>
                  <Select.Option key="1" value="1">黑白名单网络链接</Select.Option>
                  <Select.Option key="2" value="0">黑白名单文件</Select.Option>
                  <Select.Option key="3" value="5">黑白名单进程</Select.Option>
                  <Select.Option key="4" value="2">黑白流量</Select.Option>
                  <Select.Option key="5" value="4">黑白合规</Select.Option>
                </Select>,
              )}
            </Form.Item>
          </Form>
        </Modal>
        <div>{renderDefault()}</div>
      </div>
    );
  }
}

const WarpForm = Form.create({
  onValuesChange({ dispatch }, changedValues, values) {
    console.log(values);
  },
  })(Rule);

export default connect(({ policyAndrules, loading }) => ({
  policyAndrules,
  loading: loading.models.policyAndrules,
}))(WarpForm);
