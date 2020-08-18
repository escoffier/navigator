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
  Radio,
  Select,
  message,
} from 'antd';
import React, { Component, Fragment } from 'react';
import { PageHeaderWrapper } from '@ant-design/pro-layout';
import { connect } from 'dva';
import moment from 'moment';
import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import Link from 'umi/link';
import router from 'umi/router';
import StandardTable from './components/StandardTable';
import StandardFormRow from './components/StandardFormRow';
import { Pie, WaterWave, Gauge, TagCloud } from './components/Charts';
import styles from './style.less';

const FormItem = Form.Item;
const { Option } = Select;

const getValue = obj =>
  Object.keys(obj)
    .map(key => obj[key])
    .join(',');

const statusMap = ['default', 'processing', 'success', 'error'];
const status = ['停止', '运行中', '启动', '异常'];

/* eslint react/no-multi-comp:0 */
@connect(({ assetsAndtablelist, loading }) => ({
  assetsAndtablelist,
  loading: loading.models.assetsAndtablelist,
}))
class TableList extends Component {
  state = {
    modalVisible: false,
    updateModalVisible: false,
    selectedRows: [],
    formValues: {},
    stepFormValues: {},
    currentNode: 0,
  };

  columns = [
    {
      title: '容器名称',
      dataIndex: 'name',
    },
    {
      title: '镜像',
      dataIndex: 'desc',
      render: (text, record) => (
        <Fragment>
        <Link to={`/detail/image/${record.image_id}`}>{record.image}</Link>
        </Fragment>
      ),
    },
    {
      title: '问题数',
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
          text: status[0],
          value: '0',
        },
        {
          text: status[1],
          value: '1',
        },
        {
          text: status[2],
          value: '2',
        },
        {
          text: status[3],
          value: '3',
        },
      ],

      render(val) {
        return <Badge status={statusMap[val]} text={status[val]} />;
      },
    },
    {
      title: '创建时间',
      dataIndex: 'updatedAt',
      sorter: true,
      render: val => <span>{moment(val).format('YYYY-MM-DD HH:mm:ss')}</span>,
    },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          <a onClick={() => this.createRuleKey(record.key)}>配置安全规则</a>
          <Divider type="vertical" />
          <Link to={`/detail/docker/${record.key}`}>查看细节</Link>
        </Fragment>
      ),
    },
  ];

  componentDidMount() {
    const { dispatch } = this.props;
    // dispatch({
    //   type: 'assetsAndtablelist/fetch',
    // });
    dispatch({
      type: 'assetsAndtablelist/fetchContainers',
      payload: {
        node: this.state.currentNode,
      },
    })
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
      type: 'assetsAndtablelist/fetchContainers',
      payload: params,
    });
  };

  handleMenuClick = e => {
    const { dispatch } = this.props;
    const { selectedRows } = this.state;
    if (!selectedRows) return;

    switch (e.key) {
      case 'remove':
        dispatch({
          type: 'assetsAndtablelist/fetchContainers',
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
    console.log(rows);
    this.setState({
      selectedRows: rows,
    });
  };

  handleSearch = e => {
    e.preventDefault();
    const { dispatch, form } = this.props;
    const key = e.target.value;
    this.setState({
      currentNode: key,
    });

    dispatch({
      type: 'assetsAndtablelist/fetchContainers',
      payload: {
        node: key,
      },
    });
  };

  createRuleKeys = () => {
      const { selectedRows } = this.state;
      router.push({
        pathname: '/detail/rule/add',
        fillData: {
          category: 'docker',
          objects: selectedRows.map(row => `c-1-${row.key}`),
        },
      });
  };

  createRuleKey = e => {
    router.push({
      pathname: '/detail/rule/add',
      fillData: {
        category: 'docker',
        objects: [`c-1-${e}`],
      },
    });
  };


  handleUpdateModalVisible = (flag, record) => {
    this.setState({
      visible: !!flag,
      operateRecord: record || {},
    });
  };

  // handleAdd = fields => {
  //   const { dispatch } = this.props;
  //   dispatch({
  //     type: 'assetsAndtablelist/add',
  //     payload: {
  //       desc: fields.desc,
  //     },
  //   });
  //   message.success('添加成功');
  //   this.handleModalVisible();
  // };

  // handleUpdate = fields => {
  //   const { dispatch } = this.props;
  //   dispatch({
  //     type: 'assetsAndtablelist/update',
  //     payload: {
  //       name: fields.name,
  //       desc: fields.desc,
  //       key: fields.key,
  //     },
  //   });
  //   message.success('配置成功');
  //   this.handleUpdateModalVisible();
  // };

  render() {
    const {
      form: { getFieldDecorator },
    } = this.props;
    const {
      assetsAndtablelist: { data, nodes },
      loading,
    } = this.props;
    const createRuleKeys = this.createRuleKeys.bind(this);
    const { selectedRows, modalVisible, updateModalVisible, stepFormValues, currentNode } = this.state;
    // const menu = (
    //   <Menu onClick={this.handleMenuClick} selectedKeys={[]}>
    //     <Menu.Item key="remove">删除</Menu.Item>
    //     <Menu.Item key="approval">批量安全规则</Menu.Item>
    //   </Menu>
    // );
    // const parentMethods = {
    //   handleAdd: this.handleAdd,
    //   handleModalVisible: this.handleModalVisible,
    // };
    // const updateMethods = {
    //   handleUpdateModalVisible: this.handleUpdateModalVisible,
    //   handleUpdate: this.handleUpdate,
    // };

    const statTitle = (nodes && nodes.length > 1) ? (
      <Row
        style={{
          padding: '16px 0',
        }}>
            <Col span={8}>
              <div> 运行中的容器 </div>
              <Pie
                percent={Math.round(nodes[currentNode].containers.percent * 100)}
                total={`${nodes[currentNode].containers.running}/${nodes[currentNode].containers.total}`}
                height={150}
                lineWidth={2}
              />
            </Col>
            <Col span={8}>
              <div> 使用中的镜像 </div>
              <Pie
                color="#5DDECF"
                percent={Math.round(nodes[currentNode].images.percent * 100)}
                total={`${nodes[currentNode].images.running}/${nodes[currentNode].images.total}`}
                height={150}
                lineWidth={2}
              />
            </Col>
            <Col span={8}>
              <div> 节点安全威胁评分 </div>
              <Pie
                color="#c2301f"
                percent={nodes[currentNode].riskScore}
                total={<Link to="/detail/node/0">{nodes[currentNode].riskScore}</Link>}
                height={150}
                lineWidth={2}
              />
            </Col>
      </Row>
    ) : (<Row/>);

    const Info = ({ title, value, bordered }) => (
        <div className={styles.headerInfo}>
          <span>{title}</span>
          <p>{value}</p>
          {bordered && <em />}
        </div>
    );

    return (
      <PageHeaderWrapper>
        <Card bordered={false}>
          {statTitle}
        </Card>
        <Card bordered={false}>
          <Form layout="inline">
            <StandardFormRow
              title="所属节点"
              block
              style={{
                paddingBottom: 11,
              }}
            >
              <FormItem>
                {getFieldDecorator('node')(
                        <Radio.Group onChange={e => this.handleSearch(e)}>
                        <Radio.Button value="0">节点1</Radio.Button>
                        <Radio.Button value="1">节点2</Radio.Button>
                        <Radio.Button value="2">节点3</Radio.Button>
                    </Radio.Group>,
                )}
              </FormItem>
              </StandardFormRow>
          </Form>
        </Card>
        <Card bordered={false}>
          <div className={styles.tableList}>
            <div className={styles.tableListOperator}>
              {/* <Button icon="plus" type="primary" onClick={() => this.handleModalVisible(true)}> */}
                {/* 新建 */}
              {/* </Button> */}
              {selectedRows.length > 0 && (
                <span>
                  <Button onClick={() => createRuleKeys()}>批量安全规则</Button>
                  {/* <Dropdown overlay={menu}> */}
                    {/* <Button> */}
                      {/* 更多操作 <Icon type="down" /> */}
                    {/* </Button> */}
                  {/* </Dropdown> */}
                </span>
              )}
            </div>
            <StandardTable
              selectedRows={selectedRows}
              loading={loading}
              data={data}
              columns={this.columns}
              onSelectRow={this.handleSelectRows}
              onChange={this.handleStandardTableChange}
            />
          </div>
        </Card>
        {/* <CreateForm {...parentMethods} modalVisible={modalVisible} /> */}
        {/* {stepFormValues && Object.keys(stepFormValues).length ? ( */}
          {/* <UpdateForm */}
            {/* {...updateMethods} */}
            {/* updateModalVisible={updateModalVisible} */}
            {/* values={stepFormValues} */}
          {/* /> */}
        {/* ) : null} */}
      </PageHeaderWrapper>
    );
  }
}

export default Form.create()(TableList);
