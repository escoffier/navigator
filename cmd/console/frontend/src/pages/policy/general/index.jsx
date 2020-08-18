import { Button, Card, Col, Table, Form, Divider, Icon, List, Row, Select, Tag, message } from 'antd';
import React, { Component, Fragment } from 'react';
import { connect } from 'dva';
import moment from 'moment';
import Link from 'umi/link';
import StandardFormRow from './components/StandardFormRow';
import TagSelect from './components/TagSelect';
import styles from './style.less';
import router from 'umi/router';

const { Option } = Select;
const FormItem = Form.Item;
const pageSize = 5;
const formItemLayout = {
  wrapperCol: {
    xs: {
      span: 24,
    },
    sm: {
      span: 24,
    },
    md: {
      span: 12,
    },
  },
};

const categories = {
  host: '主机监控',
  monitor: '网络监控',
  dpi: '流量监控',
  image: '镜像',
  scap: '合规检查',
}
const nodes = [
  '节点3',
  '集群1',
  '集群2',
  '集群3',
  '节点1',
  '节点2',
];

let timer = null;

class General extends Component {
  state = {
    config: {
      category: '',
      level: undefined,
      owner: '00000001',
      triggers: '',
      node: '',
      loading: false,
      loadProgress: 0,
    },
  };


  componentDidMount() {
    const { dispatch } = this.props;
    const { config } = this.state;
    dispatch({
      type: 'policyAndgeneral/fetch',
      payload: config,
    });

    const { fillData } = this.props.location;
    if (fillData && fillData.cate) {
      this.setCategory(fillData.cate);
    }
  }

  setOwner = () => {
    const { form } = this.props;
    form.setFieldsValue({
      owner: ['00000001'],
    });
  };

  setCategory = (cate) => {
    const { form } = this.props;
    form.setFieldsValue({
      category: [cate || 'host'],
    });
  };

  handleAddPolicy() {
    router.push({
      pathname: '/detail/rule/add',
      fillData: {
      },
    });
  }

  handleFillDataPolicy(record) {
    router.push({
      pathname: '/detail/rule/add',
      fillData: {
        category: record.category || 'host',
        ruleName: record.name,
        objects: ['c-1', 't-1'],
        level: 4,
        alertAction: 'b',
        targetKeys: [1, 2, 3],
      },
    });
  }

  enterLoading() {
    this.setState({
      loading: true,
      loadProgress: 0,
    });

    timer = setInterval(this.progress.bind(this), 500);
  }

  progress() {
      const value = this.state.loadProgress + 10;
      this.setState({
        loadProgress: value,
      });

      if (value >= 100) {
        this.setState({
          loadProgress: 100,
          loading: false,
        });
        clearInterval(timer);
        message.success('加载推荐策略完成');
      }
    }

  render() {
    const {
      form,
      policyAndgeneral: { list },
      loading,
    } = this.props;

    const handleAddPolicy = this.handleAddPolicy.bind(this);
    const handleFillDataPolicy = this.handleFillDataPolicy.bind(this);

    const { getFieldDecorator } = form;
    const columns = [
    {
      title: '策略名称',
      dataIndex: 'name',
    },
    {
      title: '宿主',
      render: (text, record) => (
        <Link to={`/detail/node/${record.node}`}>{nodes[parseInt(record.node)]}</Link>
      ),
    },
    {
      title: '触发数',
      dataIndex: 'triggers',
      align: 'right',
      render: val => `${val}`,
      // mark to display a total number
      needTotal: true,
    },
    {
      title: '创建者',
      dataIndex: 'owner',
    },
    {
      title: '类型',
      dataIndex: 'category',
      render: val => `${categories[val]}`,
    },
    {
      title: '上次更新时间',
      dataIndex: 'updatedAt',
      render: val => <span>{moment(val).format('YYYY-MM-DD HH:mm:ss')}</span>,
    },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          <a onClick={() => handleFillDataPolicy(record)}>查看/修改</a>
        </Fragment>
      ),
    },
  ];

    const owners = [
      {
        id: '00000000',
        name: '老板',
      },
      {
        id: '00000001',
        name: '管理员',
      },
      {
        id: '00000002',
        name: '周润发',
      },
      {
        id: '00000003',
        name: '周星星',
      },
    ];
    const enterLoading = this.enterLoading.bind(this);

    return (
      <>
        <Card bordered={false}>
          <Form layout="inline">
            <StandardFormRow title="类别"
              block
              style={{
                paddingBottom: 11,
              }}>
              {getFieldDecorator('category')(
                  <TagSelect>
                    <TagSelect.Option value="host">主机监控</TagSelect.Option>
                    <TagSelect.Option value="monitor">网络监控</TagSelect.Option>
                    <TagSelect.Option value="dpi">流量监控</TagSelect.Option>
                    <TagSelect.Option value="image">镜像扫描</TagSelect.Option>
                    <TagSelect.Option value="scap">合规检测</TagSelect.Option>
                  </TagSelect>,
              )}
            </StandardFormRow>
            <StandardFormRow
              title="所属实体"
              block
              style={{
                paddingBottom: 11,
              }}
            >
              <FormItem>
                {getFieldDecorator('node')(
                  <TagSelect expandable>
                    <TagSelect.Option value="1">集群1</TagSelect.Option>
                    <TagSelect.Option value="2">集群2</TagSelect.Option>
                    <TagSelect.Option value="3">集群3</TagSelect.Option>
                    <TagSelect.Option value="4">节点1</TagSelect.Option>
                    <TagSelect.Option value="5">节点2</TagSelect.Option>
                    <TagSelect.Option value="0">节点3</TagSelect.Option>
                  </TagSelect>,
                )}
              </FormItem>
            </StandardFormRow>
            <StandardFormRow title="选择创建人" grid>
              <Row>
                <Col>
                  <FormItem {...formItemLayout}>
                    {getFieldDecorator('owner', {
                      initialValue: ['00000001'],
                    })(
                      <Select
                        mode="multiple"
                        style={{
                          maxWidth: 286,
                          width: '100%',
                        }}
                        placeholder="选择创建人"
                      >
                        {owners.map(owner => (
                          <Option key={owner.id} value={owner.id}>
                            {owner.name}
                          </Option>
                        ))}
                      </Select>,
                    )}
                    <a className={styles.selfTrigger} onClick={this.setOwner}>
                      只看自己
                    </a>
                  </FormItem>
                </Col>
              </Row>
            </StandardFormRow>
            <StandardFormRow title="选择触发条数（最近3个月）" grid>
              <Row>
                <Col>
                  <FormItem>
                    {getFieldDecorator('triggers')(
                      <TagSelect>
                        <TagSelect.Option value="0">小于10</TagSelect.Option>
                        <TagSelect.Option value="1">10~100</TagSelect.Option>
                        <TagSelect.Option value="2">100~500</TagSelect.Option>
                        <TagSelect.Option value="3">500以上</TagSelect.Option>
                      </TagSelect>,
                    )}
                  </FormItem>
                </Col>
              </Row>
            </StandardFormRow>
            <StandardFormRow title="其它选项" grid last>
              <Row gutter={16}>
                <Col xl={8} lg={10} md={12} sm={24} xs={24}>
                  <FormItem {...formItemLayout} label="警报等级">
                    {getFieldDecorator('level', {})(
                      <Select
                        style={{
                          maxWidth: 200,
                          width: '100%',
                        }}
                      >
                        <Option value="high">高优先级</Option>
                        <Option value="medium">中优先级</Option>
                        <Option value="low">低优先级</Option>
                      </Select>,
                    )}
                  </FormItem>
                </Col>
              </Row>
            </StandardFormRow>
          </Form>
        </Card>
        <Card
          style={{
            marginTop: 24,
          }}
          bordered={false}
          bodyStyle={{
            padding: '8px 32px 32px 32px',
          }}
        >
          <Row>
                <Button type="link" icon="plus" block onClick={handleAddPolicy}>
                  添加新策略
                </Button>
          </Row>
          <Row>
                <Button type="link" icon="reload" loading={this.state.loading} block onClick={enterLoading}>
                  加载推荐配置
                </Button>
          </Row>
          <Table
            dataSource={list}
            columns={columns}
          />
        </Card>
      </>
    );
  }
}

const WarpForm = Form.create({
  onValuesChange({ dispatch }, changedValues, values) {
    // 表单项变化时请求数据
    // 模拟查询表单生效
    const newvalues = {
      ...values,
      category: (values.category && values.category.length) ? values.category.join(',') : '',
      owner: (values.owner && values.owner.length) ? values.owner.join(',') : '',
      node: (values.node && values.node.length) ? values.node.join(',') : '',
      triggers: (values.triggers && values.triggers.length) ? values.triggers.join(',') : '',
      sorter: 'triggers_asc',
    };
    dispatch({
      type: 'policyAndgeneral/fetch',
      payload: newvalues,
    });
  },
})(General);

export default connect(({ policyAndgeneral, loading }) => ({
  policyAndgeneral,
  loading: loading.models.policyAndgeneral,
}))(WarpForm);
