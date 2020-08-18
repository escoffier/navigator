import { Avatar, Card, Col, Dropdown, Form, Icon, List, Menu, Row, Select, Tooltip,
  Badge,
  Button,
  DatePicker,
  Divider,
  Input,
  InputNumber,
  Tag,
  message,
} from 'antd';


import React, { Component, Fragment } from 'react';
import { connect } from 'dva';
import numeral from 'numeral';
import Link from 'umi/link';
import moment from 'moment';
import StandardFormRow from './components/StandardFormRow';
import StandardTable from './components/StandardTable';
import TagSelect from './components/TagSelect';
import styles from './style.less';

const { Option } = Select;
const FormItem = Form.Item;

const getValue = obj =>
  Object.keys(obj)
    .map(key => obj[key])
    .join(',');

const statusMap = ['default', 'processing', 'success', 'error'];
const status = ['停止', '运行中', '已完成', '异常'];


class Clusters extends Component {
  state = {
    modalVisible: false,
    updateModalVisible: false,
    expandForm: false,
    selectedRows: [],
    formValues: {},
    stepFormValues: {},
    filteredInfo: {},
  };

  handleSelectRows = rows => {
    this.setState({
      selectedRows: rows,
    });
  };

  handleDetailModalVisible = (flag, record) => {
    console.log(`${flag}:${record}`);
  };

  handleAlertDetailModalVisible = (flag, record) => {
    console.log(`${flag}:${record}`);
  };

  handleStandardTableChange = (pagination, filtersArg, sorter) => {
    const { dispatch } = this.props;
    const { formValues } = this.state;
    console.log(filtersArg);

    // const filters = Object.keys(filtersArg).reduce((obj, key) => {
    //   const newObj = { ...obj };
    //   newObj[key] = getValue(filtersArg[key]);
    //   return newObj;
    // }, {});

    this.setState({
      filteredInfo: filtersArg,
    });

    const params = {
      currentPage: pagination.current,
      pageSize: pagination.pageSize,
      ...formValues,
      // ...filters,
    };

    if (sorter.field) {
      params.sorter = `${sorter.field}_${sorter.order}`;
    }

    dispatch({
      type: 'assetsAndclusters/fetch',
      payload: params,
    });
  };

  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'assetsAndclusters/fetch',
      payload: {type: ['node']}
    });
  }

  constructFilters(obj) {
    return obj.map(child => ({
          text: child,
          value: child,
        }))
  }

  render() {
    const {
      assetsAndclusters: { data },
      loading,
      form,
    } = this.props;

    const { selectedRows, filteredInfo } = this.state;
    const { getFieldDecorator } = form;
    const columnNameSpaceSelect = (data && data.meta && data.meta.namespaces) ? this.constructFilters(data.meta.namespaces) : [];
    const columnTypeSelect = (data && data.meta && data.meta.categories) ? this.constructFilters(data.meta.categories) : [];

    const columns = [
    {
      title: '实体名称',
      dataIndex: 'name',
    },
    {
      title: '类型',
      dataIndex: 'type',
      filters: columnTypeSelect,
      filteredValue: filteredInfo.type || null,
      onFilter: (value, record) => record.type.includes(value),
    },
    {
    title: '标签',
    key: 'tags',
    dataIndex: 'tags',
    render: tags => (
      <span>
        {tags.map(tag => {
          let color = tag.length > 5 ? 'geekblue' : 'green';
          if (tag === 'production') {
            color = 'volcano';
          }
          return (
            <Tag color={color} key={tag}>
              {tag.toUpperCase()}
            </Tag>
          );
        })}
      </span>
      ),
    },
    {
      title: '命名空间',
      dataIndex: 'namespace',
      filters: columnNameSpaceSelect,
      filteredValue: filteredInfo.namespace || null,
      onFilter: (value, record) => record.namespace.includes(value),
    },
    {
      title: '状态',
      dataIndex: 'status',
      filteredValue: filteredInfo.status || null,
      onFilter: (value, record) => parseInt(value) === record.status,
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
      title: '上次更新时间',
      dataIndex: 'updatedAt',
      sorter: true,
      render: val => <span>{moment(val).format('YYYY-MM-DD HH:mm:ss')}</span>,
    },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          <Link to={`/detail/${(record.type || '').toLowerCase()}/${record.key}`}>查看细节</Link>
          <Divider type="vertical" />
          <a onClick={() => this.handleAlertDetailModalVisible(true, record)}>隔离</a>
        </Fragment>
      ),
    },
  ];


    const formItemLayout = {
      wrapperCol: {
        xs: {
          span: 24,
        },
        sm: {
          span: 16,
        },
      },
    };

    return (
      <div className={styles.filterCardList}>
        <Card bordered={false}>
          <Form layout="inline">
            <StandardFormRow
              title="资源类别"
              block
              style={{
                paddingBottom: 11,
              }}
            >
              <FormItem>
                {getFieldDecorator('type', {
                  initialValue: ['node'],
                })(
                  <TagSelect hideCheckAll>
                    <TagSelect.Option value="node">主机</TagSelect.Option>
                    <TagSelect.Option value="pod">Pod容器</TagSelect.Option>
                    <TagSelect.Option value="endpoint">网络节点</TagSelect.Option>
                  </TagSelect>,
                )}
              </FormItem>
              </StandardFormRow>
          </Form>
        </Card>
        <br />
        <StandardTable
              selectedRows={selectedRows}
              loading={loading}
              data={data}
              columns={columns}
              onSelectRow={this.handleSelectRows}
              onChange={this.handleStandardTableChange}
        />
      </div>
    );
  }
}

const WarpForm = Form.create({
  onValuesChange({ dispatch }, changedValues, values) {
    // 表单项变化时请求数据
    // 模拟查询表单生效
    const newvalues = {
      ...values,
      type: (values.type) ? values.type.join(',') : '',
    };

    dispatch({
      type: 'assetsAndclusters/fetch',
      payload: newvalues,
    });
  },
})(Clusters);
export default connect(({ assetsAndclusters, loading }) => ({
  assetsAndclusters,
  loading: loading.models.assetsAndclusters,
}))(WarpForm);
