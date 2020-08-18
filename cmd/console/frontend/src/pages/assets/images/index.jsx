import {
  Badge,
  Button,
  Card,
  Col,
  DatePicker,
  Divider,
  Dropdown,
  Form,
  Icon,
  Input,
  InputNumber,
  Menu,
  Row,
  Select,
  message,
  Modal,
} from 'antd';
import router from 'umi/router';
import React, { Component, Fragment } from 'react';
import Link from 'umi/link';
import { PageHeaderWrapper } from '@ant-design/pro-layout';
import { connect } from 'dva';
import moment from 'moment';
import StandardTable from './components/StandardTable';
import VulnerabilityBar from './components/VulnerabilityBar';
import styles from './style.less';

const FormItem = Form.Item;
const { Option } = Select;

const getValue = obj =>
  Object.keys(obj)
    .map(key => obj[key])
    .join(',');

const statusMap = ['success', 'error'];
const status = ['正常', '禁用'];
const colors = ['#eb3926', '#c9830e', '#25ce8b'];
const levels = ['严重', '中等', '低等'];

const getVulnerabilityBar = objs => {
  return (objs.map((obj, key) => {
    return {
      value: obj.number,
      color: colors[obj.key],
      tooltip: `${levels[obj.key]}: ${obj.number}`,
    }
  }));
};

/* eslint react/no-multi-comp:0 */
@connect(({ assetsAndimages, loading }) => ({
  assetsAndimages,
  loading: loading.models.assetsAndimages,
}))


class ImageList extends Component {
  state = {
    expandForm: false,
    selectedRows: [],
    visible: false,
    formValues: {},
    operateRecord: {},
  };

  operations = [{ text: '禁用', color: 'warning' }, { text: '使用', color: 'primary' } ];

  columns = [
    {
      title: '镜像全名',
      dataIndex: 'name',
    },
    {
      title: '镜像仓库',
      dataIndex: 'repo',
    },
    {
      title: '镜像标签',
      dataIndex: 'tag',
    },
    {
      title: '相关容器数',
      dataIndex: 'callNo',
      sorter: true,
      align: 'right',
      render: val => `${val}`,
      // mark to display a total number
      needTotal: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      filters: [
        {
          text: '正常',
          value: '0',
        },
        {
          text: '禁用',
          value: '1',
        },
      ],

      render(val) {
        return <Badge status={statusMap[val]} text={status[val]} />;
      },
    },
    {
      title: '镜像漏洞  ',
      dataIndex: 'vulnerabilities',
      align: 'right',
      render(val) {
        return <VulnerabilityBar data={getVulnerabilityBar(val)}/>;
      },
    },
    {
      title: '上次扫描时间',
      dataIndex: 'updatedAt',
      sorter: true,
      render: val => <span>{moment(val).format('YYYY-MM-DD HH:mm:ss')}</span>,
    },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          {<a onClick={() => this.handleUpdateModalVisible(true, record)}>{this.operations[parseInt(record.status) || 0].text}</a>}
          <Divider type="vertical" />
          <Link to={`/detail/image/${record.key}`}>查看细节</Link>
        </Fragment>
      ),
    },
  ];

  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'assetsAndimages/fetch',
    });
  }

  handleStandardTableChange = (pagination, filtersArg, sorter) => {
    const { dispatch } = this.props;
    const { formValues } = this.state;
    const filters = Object.keys(filtersArg).reduce((obj, key) => {
      const newObj = { ...obj };
      newObj[key] = getValue(filtersArg[key]);
      return newObj;
    }, {});
    const params = {
      currentPage: pagination.current,
      pageSize: pagination.pageSize,
      ...formValues,
      ...filters,
    };

    if (sorter.field) {
      params.sorter = `${sorter.field}_${sorter.order}`;
    }

    dispatch({
      type: 'assetsAndimages/fetch',
      payload: params,
    });
  };

  handleFormReset = () => {
    const { form, dispatch } = this.props;
    form.resetFields();
    this.setState({
      formValues: {},
    });
    dispatch({
      type: 'assetsAndimages/fetch',
      payload: {},
    });
  };

  toggleForm = () => {
    const { expandForm } = this.state;
    this.setState({
      expandForm: !expandForm,
    });
  };

  handleMenuClick = e => {
    const { dispatch } = this.props;
    const { selectedRows } = this.state;
    if (!selectedRows) return;

    switch (e.key) {
      case 'remove':
        dispatch({
          type: 'assetsAndimages/block',
          payload: {
            key: selectedRows.map(row => row.key),
          },
          callback: () => {
            this.setState({
              selectedRows: [],
            });
          },
        });
        break;

      default:
        break;
    }
  };

  handleSelectRows = rows => {
    this.setState({
      selectedRows: rows,
    });
  };

  handleSearch = e => {
    e.preventDefault();
    const { dispatch, form } = this.props;
    form.validateFields((err, fieldsValue) => {
      if (err) return;
      const values = {
        ...fieldsValue,
        updatedAt: fieldsValue.updatedAt && fieldsValue.updatedAt.valueOf(),
      };
      this.setState({
        formValues: values,
      });

      if (values.date) {
        console.log(values.date.isAfter(new Date('2019-07-01')));
      }

      dispatch({
        type: 'assetsAndimages/fetch',
        payload: values,
      });
    });
  };

  handleModalVisible = flag => {
    this.setState({
      visible: !!flag,
    });
  };

  handleUpdateModalVisible = (flag, record) => {
    this.setState({
      visible: !!flag,
      operateRecord: record || {},
    });
  };

  handleAdd = fields => {
    const { dispatch } = this.props;
    dispatch({
      type: 'assetsAndimages/allow',
      payload: {
        desc: fields.desc,
      },
    });
    message.success('添加成功');
    this.handleModalVisible();
  };

  handleUpdate = fields => {
    const { dispatch } = this.props;
    dispatch({
      type: 'assetsAndimages/scan',
      payload: {
        name: fields.name,
        desc: fields.desc,
        key: fields.key,
      },
    });
    message.success('配置成功');
    this.handleUpdateModalVisible();
  };

  handleModalCancel= event => {
    this.setState({
      visible: false,
    })
  };

  handleModalOk = event => {
    this.handleModalCancel();
  };

  renderSimpleForm() {
    const { form } = this.props;
    const { getFieldDecorator } = form;
    return (
      <Form onSubmit={this.handleSearch} layout="inline">
        <Row
          gutter={{
            md: 8,
            lg: 24,
            xl: 48,
          }}
        >
          <Col md={8} sm={24}>
            <FormItem label="名称">
              {getFieldDecorator('name')(<Input placeholder="请输入" />)}
            </FormItem>
          </Col>
          <Col md={8} sm={24}>
            <FormItem label="使用状态">
              {getFieldDecorator('status')(
                <Select
                  placeholder="请选择"
                  style={{
                    width: '100%',
                  }}
                >
                  <Option value="0">正常</Option>
                  <Option value="1">禁用</Option>
                </Select>,
              )}
            </FormItem>
          </Col>
          <Col md={8} sm={24}>
            <span className={styles.submitButtons}>
              <Button type="primary" htmlType="submit">
                查询
              </Button>
              <Button
                style={{
                  marginLeft: 8,
                }}
                onClick={this.handleFormReset}
              >
                重置
              </Button>
              <a
                style={{
                  marginLeft: 8,
                }}
                onClick={this.toggleForm}
              >
                展开 <Icon type="down" />
              </a>
            </span>
          </Col>
        </Row>
      </Form>
    );
  }

  renderAdvancedForm() {
    const {
      form: { getFieldDecorator },
    } = this.props;
    return (
      <Form onSubmit={this.handleSearch} layout="inline">
        <Row
          gutter={{
            md: 8,
            lg: 24,
            xl: 48,
          }}
        >
          <Col md={8} sm={24}>
            <FormItem label="镜像名称">
              {getFieldDecorator('name')(<Input placeholder="请输入" />)}
            </FormItem>
          </Col>
          <Col md={6} sm={24}>
            <FormItem label="使用状态">
              {getFieldDecorator('status')(
                <Select
                  placeholder="请选择"
                  style={{
                    width: '100%',
                  }}
                >
                  <Option value="0">正常</Option>
                  <Option value="1">禁用</Option>
                </Select>,
              )}
            </FormItem>
          </Col>
          <Col md={5} sm={24}>
            <FormItem label="相关容器数（>=）">
              {getFieldDecorator('numberAbove')(
                <InputNumber
                  style={{
                    width: '100%',
                  }}
                />,
              )}
            </FormItem>
          </Col>
          <Col md={5} sm={24}>
            <FormItem label="相关容器数（<）">
              {getFieldDecorator('numberBelow')(
                <InputNumber
                  style={{
                    width: '100%',
                  }}
                />,
              )}
            </FormItem>
          </Col>
        </Row>
        <Row
          gutter={{
            md: 8,
            lg: 24,
            xl: 48,
          }}
        >
          <Col md={8} sm={24}>
            <FormItem label="上次扫描日期早于">
              {getFieldDecorator('date')(
                <DatePicker
                  style={{
                    width: '100%',
                  }}
                  placeholder="请输入更新日期"
                />,
              )}
            </FormItem>
          </Col>
          <Col md={8} sm={24}>
            <FormItem label="仓库名称">
              {getFieldDecorator('repoName')(
                <Select
                  placeholder="请选择"
                  style={{
                    width: '100%',
                  }}
                >
                  <Option value="0">Dockerhub 公有</Option>
                  <Option value="1">Private</Option>
                </Select>,
              )}
            </FormItem>
          </Col>
          <Col md={8} sm={24}>
            <FormItem label="镜像Sha">
              {getFieldDecorator('sha')(
                <Input placeholder="请输入Sha名称" />,
              )}
            </FormItem>
          </Col>
        </Row>
        <div
          style={{
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              float: 'right',
              marginBottom: 24,
            }}
          >
            <Button type="primary" htmlType="submit">
              查询
            </Button>
            <Button
              style={{
                marginLeft: 8,
              }}
              onClick={this.handleFormReset}
            >
              重置
            </Button>
            <a
              style={{
                marginLeft: 8,
              }}
              onClick={this.toggleForm}
            >
              收起 <Icon type="up" />
            </a>
          </div>
        </div>
      </Form>
    );
  }

  renderForm() {
    const { expandForm } = this.state;
    return expandForm ? this.renderAdvancedForm() : this.renderSimpleForm();
  }

  handleAddPolicy() {
      router.push({
        pathname: '/detail/rule/add',
        fillData: {
          category: 'image',
        },
    });
  }

  render() {
    const {
      assetsAndimages: { data },
      loading,
    } = this.props;
    const { selectedRows, visible, operateRecord } = this.state;
    const handleAddPolicy = this.handleAddPolicy.bind(this);
    const menu = (
      <Menu onClick={this.handleMenuClick} selectedKeys={[]}>
        <Menu.Item key="disable">批量禁用</Menu.Item>
      </Menu>
    );

    return (
      <PageHeaderWrapper>
        <Card bordered={false}>
          <div className={styles.tableList}>
            <div className={styles.tableListForm}>{this.renderForm()}</div>
            <div className={styles.tableListOperator}>
              {selectedRows.length > 0 && (
                <span>
                  <Button onClick={() => handleAddPolicy()}>对选择项目创建规则</Button>
                  <Dropdown overlay={menu}>
                    <Button>
                      更多操作 <Icon type="down" />
                    </Button>
                  </Dropdown>
                </span>
              )}
            </div>
            <StandardTable
              selectedRows={selectedRows}
              loading={loading}
              data={data}
              columns={this.columns}
              expandedRowRender={record => <p style={{ margin: 0 }}>{record.sha}</p>}
              onSelectRow={this.handleSelectRows}
              onChange={this.handleStandardTableChange}
            />
          </div>
        </Card>
        <Modal
          title="确认"
          visible={visible}
          onOk={this.handleModalOk}
          onCancel={this.handleModalCancel}
        >
          <p>{`确认修改 ${operateRecord.name} 状态为 ${status[(operateRecord.status + 1) % 2]}?`}</p>
        </Modal>
      </PageHeaderWrapper>
    );
  }
}

export default Form.create()(ImageList);
