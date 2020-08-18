import {
  Avatar,
  Badge,
  Button,
  Card,
  Col,
  Divider,
  DatePicker,
  Dropdown,
  Form,
  Icon,
  Input,
  InputNumber,
  List,
  Menu,
  Modal,
  Progress,
  Radio,
  Row,
  Select,
  Result,
} from 'antd';

import router from 'umi/router';
import Link from 'umi/link';
import React, { Component, Fragment } from 'react';
import { PageHeaderWrapper, GridContent, RouteContext} from '@ant-design/pro-layout';
import { connect } from 'dva';
import { findDOMNode } from 'react-dom';
import moment from 'moment';
import styles from './style.less';
import StandardTable from './components/StandardTable';
import StatusStep from './components/StatusStep';

const { RangePicker } = DatePicker;
const FormItem = Form.Item;
const RadioButton = Radio.Button;
const RadioGroup = Radio.Group;
const SelectOption = Select.Option;
const { Search, TextArea } = Input;

function statsTotal(arr, field, value) {
  const testArr = arr || [];
  return testArr.reduce((total, next) => {
    if (field) {
       if (next[field] === value) {
        total = total + 1;
      }
    } else {
      total = total + 1;
    }

    return total
  }, 0);
}

const statusMap = ['error', 'warning', 'default'];
const taskStatusMap = ['default', 'processing', 'success', 'error'];
const labels = ['严重', '中等', '轻度'];
const taskLabels = ['初始', '处理中', '完成', '忽略'];
const getValue = obj =>
  Object.keys(obj)
    .map(key => obj[key])
    .join(',');

const cates = ['网络监测', '流量过滤', '文件监测', '进程监测', '提权', '漏洞利用'];

const columns = [
    {
      title: '源头',
      render: (text, record) => (
        <Fragment>
          <Link to={`/detail/docker/${record.source.key}`}> {record.source.name} </Link>
        </Fragment>
      ),
    },
    {
      title: '类型',
      dataIndex: 'category',
      filters: cates.map((item, k) => {
        return ({text: item, value: k})
      }),
      render(val) {
        return cates[val];
      },
    },
    {
      title: '创建时间',
      dataIndex: 'updatedAt',
      sorter: true,
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      filters: [
        {
          text: '严重',
          value: '0',
        },
        {
          text: '中度',
          value: '1',
        },
        {
          text: '轻度',
          value: '2',
        },
      ],
      sorter: true,
      render(val) {
        return <Badge status={statusMap[val]} text={labels[val]} />;
      },
    },
    {
      title: '处理状态',
      dataIndex: 'status',
      filters: taskLabels.map((item, k) => {
        return ({text: item, value: k})
      }),
      render(val) {
        return <Badge status={taskStatusMap[val]} text={taskLabels[val]} />;
      },
    },
    {
      title: '负责人',
      dataIndex: 'owner',
    },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          {<a onClick={() => {}}> {record.status === 3 ? "": "忽略此告警"} </a>}
          <Divider type="vertical" />
          {
            (record.disabled) ? <Link to={`/detail/${record.taskId}`}>查看处理进度</Link> : ''
          }
        </Fragment>
      ),
    },
  ];

@connect(({ alertsAndoverview, user, loading }) => ({
  alertsAndoverview,
  user,
  loading: loading.models.alertsAndoverview,
}))
class Overview extends Component {
  state = {
    visible: false,
    done: false,
    expandForm: false,
    current: undefined,
    displayList: [],
    selectedRows: [],
    formValues: {},
  };

  formLayout = {
    labelCol: {
      span: 7,
    },
    wrapperCol: {
      span: 13,
    },
  };

  addBtn = undefined;

  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'alertsAndoverview/fetch',
    });
  }

  showModal = () => {
    this.setState({
      visible: true,
      current: undefined,
    });
  };

  handleSelectRows = rows => {
      this.setState({
        selectedRows: rows,
      });
  };

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

      console.log(params);
      dispatch({
        type: 'alertsAndoverview/fetch',
        payload: params,
      });
  };

  showEditModal = item => {
    this.setState({
      visible: true,
      current: item,
    });
  };

  handleDone = () => {
    setTimeout(() => this.addBtn && this.addBtn.blur(), 0);
    this.setState({
      done: false,
      visible: false,
      unhandledChecked: false,
      mineChecked: false,
    });
  };

  handleCancel = () => {
    setTimeout(() => this.addBtn && this.addBtn.blur(), 0);
    this.setState({
      visible: false,
    });
  };

  handleCreateHandleTask = () => {
    const { selectedRows } = this.state;
    router.push({
        pathname: '/detail/handletask/new',
        query: {
          alerts: selectedRows,
        },
    });
  };

  handleSubmit = e => {
    e.preventDefault();
    const { dispatch, form } = this.props;
    const { current } = this.state;
    const id = current ? current.id : '';
    setTimeout(() => this.addBtn && this.addBtn.blur(), 0);
    form.validateFields((err, fieldsValue) => {
      if (err) return;
      this.setState({
        done: true,
      });
      dispatch({
        type: 'alertsAndoverview/submit',
        payload: {
          id,
          ...fieldsValue,
        },
      });
    });
  };

  handleSearch = (e) => {
    e.preventDefault();
    const { dispatch, form } = this.props;
    form.validateFields((err, fieldsValue) => {
      const values = {
        ...fieldsValue,
      };
      this.setState({
        formValues: values,
      });

      console.log(values);

      dispatch({
        type: 'alertsAndoverview/fetch',
        payload: values,
      });
    });
  };

  deleteItem = id => {
    const { dispatch } = this.props;
    dispatch({
      type: 'alertsAndoverview/submit',
      payload: {
        id,
      },
    });
  };

  toggleForm = () => {
    const { expandForm } = this.state;
    this.setState({
      expandForm: !expandForm,
    });
  };

  handleSearchHeader = (cate) => {
    const { dispatch } = this.props;
    console.log(cate);
    dispatch({
      type: 'alertsAndoverview/fetch',
      payload: cate,
    });
  };

  handleFormReset = () => {
    const { form, dispatch } = this.props;
    form.resetFields();
    this.setState({
      formValues: {},
    });
    dispatch({
      type: 'alertsAndoverview/fetch',
      payload: {},
    });
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
            <FormItem label="告警关键词">
              {getFieldDecorator('name')(<Input placeholder="请输入" />)}
            </FormItem>
          </Col>
          <Col md={6} sm={24}>
            <FormItem label="告警时间">
              {getFieldDecorator('date')(
                <RangePicker/>,
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
          <Col md={6} sm={24}>
            <FormItem label="告警关键词">
              {getFieldDecorator('name')(<Input placeholder="请输入" />)}
            </FormItem>
          </Col>
          <Col md={6} sm={24}>
            <FormItem label="告警时间">
              {getFieldDecorator('date')(
                <RangePicker/>,
              )}
            </FormItem>
          </Col>
          <Col md={8} sm={24}>
            <FormItem label="负责人">
              {getFieldDecorator('ownerId')(
                <Select
                  placeholder="请选择"
                  style={{
                    width: '100%',
                  }}
                >
                  <Option value="00000000">老板</Option>
                  <Option value="00000001">管理员</Option>
                  <Option value="00000002">周润发</Option>
                  <Option value="00000003">周星星</Option>
                </Select>,
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

  render() {
    const {
      alertsAndoverview: { list },
      user: {currentUser},
      loading,
    } = this.props;
    // const {
    //   form: { getFieldDecorator },
    // } = this.props;
    const { visible, done, current = {}, unhandledChecked, mineChecked, selectedRows} = this.state;
    const handleSelectRows = this.handleSelectRows.bind(this);
    const handleStandardTableChange = this.handleStandardTableChange.bind(this);
    const handleSearchHeader = this.handleSearchHeader.bind(this);
    const handleCreateHandleTask = this.handleCreateHandleTask.bind(this);

    const editAndDelete = (key, currentItem) => {
      if (key === 'edit') this.showEditModal(currentItem);
      else if (key === 'delete') {
        Modal.confirm({
          title: '忽略告警',
          content: '确定忽略该告警吗？',
          okText: '确认',
          cancelText: '取消',
          onOk: () => this.deleteItem(currentItem.id),
        });
      }
    };

    const modalFooter = done
      ? {
          footer: null,
          onCancel: this.handleDone,
        }
      : {
          okText: '保存',
          onOk: this.handleSubmit,
          onCancel: this.handleCancel,
        };

    const Info = ({ title, value, bordered }) => (
      <div className={styles.headerInfo}>
        <span>{title}</span>
        <p>{value}</p>
        {bordered && <em />}
      </div>
    );

    // const getModalContent = () => {
    //   if (done) {
    //     return (
    //       <Result
    //         status="success"
    //         title="操作成功"
    //         subTitle="一系列的信息描述，很短同样也可以带标点。"
    //         extra={
    //           <Button type="primary" onClick={this.handleDone}>
    //             知道了
    //           </Button>
    //         }
    //         className={styles.formResult}
    //       />
    //     );
    //   }
    //
    //   return (
    //     <Form onSubmit={this.handleSubmit}>
    //       <FormItem label="任务名称" {...this.formLayout}>
    //         {getFieldDecorator('title', {
    //           rules: [
    //             {
    //               required: true,
    //               message: '请输入任务名称',
    //             },
    //           ],
    //           initialValue: current.title,
    //         })(<Input placeholder="请输入" />)}
    //       </FormItem>
    //       <FormItem label="开始时间" {...this.formLayout}>
    //         {getFieldDecorator('createdAt', {
    //           rules: [
    //             {
    //               required: true,
    //               message: '请选择开始时间',
    //             },
    //           ],
    //           initialValue: current.createdAt ? moment(current.createdAt) : null,
    //         })(
    //           <DatePicker
    //             showTime
    //             placeholder="请选择"
    //             format="YYYY-MM-DD HH:mm:ss"
    //             style={{
    //               width: '100%',
    //             }}
    //           />,
    //         )}
    //       </FormItem>
    //       <FormItem label="任务负责人" {...this.formLayout}>
    //         {getFieldDecorator('owner', {
    //           rules: [
    //             {
    //               required: true,
    //               message: '请选择任务负责人',
    //             },
    //           ],
    //           initialValue: current.owner,
    //         })(
    //           <Select placeholder="请选择">
    //             <SelectOption value="付晓晓">付晓晓</SelectOption>
    //             <SelectOption value="周毛毛">周毛毛</SelectOption>
    //           </Select>,
    //         )}
    //       </FormItem>
    //       <FormItem {...this.formLayout} label="产品描述">
    //         {getFieldDecorator('subDescription', {
    //           rules: [
    //             {
    //               message: '请输入至少五个字符的产品描述！',
    //               min: 5,
    //             },
    //           ],
    //           initialValue: current.subDescription,
    //         })(<TextArea rows={4} placeholder="请输入至少五个字符" />)}
    //       </FormItem>
    //     </Form>
    //   );
    // };
    const myList = list.filter((item) => {return item.ownerId === currentUser.userid});
    const unhandled = statsTotal(myList, 'status', 1) || 0;
    const criticals = statsTotal(list, 'severity', 0) || 0;
    const ongoings = statsTotal(list, 'status', 1) || 0;
    const catePieData = [0, 1, 2, 3, 4, 5].map((i) => {
      return statsTotal(list, 'category', i) || 0;
    });
    const query = {ownerId: currentUser.userid, status: 1};
    const queryCritical = {severity: "0"};
    const queryTask = {status: 1};

    const statHeader = (
       <Card bordered={false}>
              <Row>
                <Col sm={8} xs={24}>
                  <a onClick={() => handleSearchHeader(query)}><Info title="我的待办" value={unhandled} bordered /></a>
                </Col>
                <Col sm={8} xs={24}>
                  <a onClick={() => handleSearchHeader(queryCritical)}><Info title="严重告警数" value={criticals} bordered /></a>
                </Col>
                <Col sm={8} xs={24}>
                  <a onClick={() => handleSearchHeader(queryTask)}><Info title="进行中告警处理任务" value={ongoings} /></a>
                </Col>
              </Row>
       </Card>
    );

    const displayList = {
      list: list,
      pagination: null,
    }

    return (
      <>
        <PageHeaderWrapper>
          <div className={styles.standardList}>
            {statHeader}
            <Card bordered={false}>
              <div className={styles.tableList}>
                <div className={styles.tableListForm}>{this.renderForm()}</div>
                <div className={styles.tableListOperator}>
                  {selectedRows.length > 0 && (
                    <span>
                      <Button onClick={() => handleCreateHandleTask()}>对选择报警统一处理</Button>
                      <Button>忽略选中报警</Button>
                    </span>
                  )}
                </div>
              </div>
            </Card>
            <Card bordered={false}>
            <StandardTable
              selectedRows={selectedRows}
              loading={loading}
              data={displayList}
              columns={columns}
              onSelectRow={handleSelectRows}
              onChange={handleStandardTableChange}
              expandedRowRender={record => <p style={{ margin: 0 }}>{record.content}</p>}
            />
            </Card>
          </div>
        </PageHeaderWrapper>

        <Modal
          title={done ? null : `任务${current ? '编辑' : '添加'}`}
          className={styles.standardListForm}
          width={640}
          bodyStyle={
            done
              ? {
                  padding: '72px 0',
                }
              : {
                  padding: '28px 0 0',
                }
          }
          destroyOnClose
          visible={visible}
          {...modalFooter}
        >
          {/*{getModalContent()}*/}
        </Modal>
      </>
    );
  }
}

export default Form.create()(Overview);
