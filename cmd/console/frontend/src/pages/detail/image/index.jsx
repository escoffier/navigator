// import { Card, Col, Form, List, Row, Select, Typography } from 'antd';
import {
  Badge,
  Button,
  Card,
  Statistic,
  Descriptions,
  Divider,
  Dropdown,
  Icon,
  Menu,
  Modal,
  Popover,
  Progress,
  Steps,
  Table,
  Tag,
  Row,
  Col,
  Tabs, List,
} from 'antd';
import Link from 'umi/link';

import { GridContent, PageHeaderWrapper, RouteContext } from '@ant-design/pro-layout';
import React, { Component, Fragment } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import StandardTable from './components/StandardTable';
import VtPie from './components/VtPie';
import styles from './style.less';


const ButtonGroup = Button.Group;
const { TabPane } = Tabs;


const statusMap = ['error', 'warning', 'default'];
const labels = ['严重', '中等', '轻度'];
const status = ['启用', '禁用'];
const operations = ['加入白名单', '移除白名单'];

const getValue = obj =>
  Object.keys(obj)
    .map(key => obj[key])
    .join(',');

let timer = null;

@connect(({ image: { detail, vulns, files, commands, packages }, loading }) => ({
  detail,
  vulns,
  files,
  commands,
  packages,
  loading: loading.models.image,
}))

class ImageDetail extends Component {
    state = {
      visible: false,
      operateRecord: {},
      selectedRows: [],
      currentTabKey: '0',
      alert: false,
      fixSolution: null,
      scanProgress: 100,
      fileDetail: false,
      fileDetailRow: null,
    };

    columnsVuln = [
    {
      title: '漏洞名',
      render: (text, record) => (
        <a href={record.lnk}> {record.name} </a>
      ),
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
    // {
    //   title: '是否为白名单',
    //   dataIndex: 'inwhite',
    //   render(val) {
    //     return (val ? '是' : '否');
    //   },
    // },
    {
      title: '影响模块',
      dataIndex: 'component',
    },
    // {
    //   title: '所在镜像层',
    //   dataIndex: 'layer',
    // },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          {<a onClick={() => this.handleUpdateModalVisible(true, record)}>{record.inwhite ? operations[1] : operations[0]}</a>}
          <Divider type="vertical" />
          <a onClick={() => this.handleVulnFix(record)}>{record.hasFix ? '自动补丁' : ''}</a>
        </Fragment>
      ),
    },
  ];

    columnsFile = [
    {
      title: '文件名',
      render: (text, record) => (
        <a onClick={() => this.handleFileDetail(record)}> {record.name} </a>
      ),
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
    // {
    //   title: '是否为白名单',
    //   dataIndex: 'inwhite',
    //   render(val) {
    //     return (val ? '是' : '否');
    //   },
    // },
    {
      title: '文件路径',
      dataIndex: 'component',
    },
    // {
    //   title: '所在镜像层',
    //   dataIndex: 'layer',
    // },
    {
      title: '操作',
      render: (text, record) => (
        <Fragment>
          {<a onClick={() => this.handleUpdateModalVisible(true, record)}>{record.inwhite ? operations[1] : operations[0]}</a>}
        </Fragment>
      ),
    },
  ];

    columnsHistory = [
      {
        title: '序号',
        dataIndex: 'name',
      },
      {
        title: '命令',
        dataIndex: 'description',
      },
      {
        title: '哈希',
        dataIndex: "sha",
      },
      {
        title: '包含漏洞数',
        dataIndex: "vulnerabilities",
      },
    ];

    columnsPackages = [
      {
        title: '名称',
        dataIndex: 'name',
      },
      {
        title: '源',
        dataIndex: 'source',
      },
      {
        title: '路径',
        dataIndex: 'path',
      },
      {
        title: '版本',
        dataIndex: 'version',
      },
      {
        title: '包含漏洞数',
        dataIndex: "vulnerabilities",
      },
    ];

    progress() {
      const value = this.state.scanProgress + 1;
      this.setState({
        scanProgress: value,
      })

      if (value >= 100) {
        this.setState({
          scanProgress: 100,
        });
        clearInterval(timer);
      }
    }

    handleFileDetail(record) {
      this.setState({
        fileDetail: true,
        fileDetailRow: record,
      })
    }

    handleFileOk(record) {
      this.setState({
        fileDetail: false,
        fileDetailRow: record,
      })
    }


    handleVulnOk(record) {
      this.setState({
        alert: false,
        fixSolution: null,
      })
    }

    handleVulnCancel(record) {
      this.setState({
        alert: false,
        fixSolution: null,
      })
    }

    handleVulnFix(record) {
      this.setState({
        alert: true,
        fixSolution: record.fix,
      })
    }

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    handleTabChange = key => {
      this.setState({
      currentTabKey: key,
      });
    };

    handleUpdateModalVisible = (flag, record) => {
      this.setState({
        visible: !!flag,
        operateRecord: record || {},
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

      dispatch({
        type: 'image/fetchVulns',
        payload: params,
      });
    };

    handleStartScan() {
      this.setState({
        scanProgress: 0,
      })
      timer = setInterval(this.progress.bind(this), 500);
    }

    componentDidMount() {
      const { dispatch } = this.props;
      dispatch({
        type: 'image/fetchDetail',
        payload: this.props.match.params.image || 0,
      });
      dispatch({
        type: 'image/fetchVulns',
        payload: this.props.match.params.image || 0,
      });
      dispatch({
        type: 'image/fetchFiles',
        payload: this.props.match.params.image || 0,
      });
      dispatch({
        type: 'image/fetchCommands',
        payload: this.props.match.params.image || 0,
      });
      dispatch({
        type: 'image/fetchPackages',
        payload: this.props.match.params.image || 0,
      });
    }

    render() {
      const {
        detail,
        vulns,
        files,
        commands,
        packages,
        loading,
      } = this.props;

      const { selectedRows, currentTabKey, alert, fixSolution,
        scanProgress, fileDetail, fileDetailRow } = this.state;

      const handleClick = this.handleClick.bind(this);
      const handleVulnOk = this.handleVulnOk.bind(this);
      const handleVulnCancel = this.handleVulnCancel.bind(this);
      const handleFileOk = this.handleFileOk.bind(this);

      const extra = (
        <div className={styles.moreInfo}>
          <Statistic title="状态" value={status[detail.status || 0]} />
          <Statistic title="相关漏洞数" value={detail.total} />
          <div>
          <Progress type="circle" percent={scanProgress} width={60}/>
          </div>
        </div>
      );

      const tmpTags = detail.tags || [];
      const tags = (<span>
        {tmpTags.map(tag => {
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
      </span>)


      const description = (
            <Descriptions className={styles.headerList} size="small" column={2}>
              <Descriptions.Item label="创建人">{detail.owner || ''}</Descriptions.Item>
              <Descriptions.Item label="镜像仓库类型">{detail.namespace || ''}</Descriptions.Item>
               <Descriptions.Item label="操作系统"> {detail.os || ''}</Descriptions.Item>
              <Descriptions.Item label="更新时间">{detail.updated}</Descriptions.Item>
              <Descriptions.Item label="标签">{detail.tags}</Descriptions.Item>
              <Descriptions.Item label="使用中容器">
                <List
                  bordered
                  dataSource={detail.containers}
                  renderItem={item => <Tag color="blue"><Link to={`/detail/pod/${item}`}>容器{item}</Link></Tag>}
                />
              </Descriptions.Item>
              <Descriptions.Item label="镜像哈希" span={2} >{detail.id || ''}</Descriptions.Item>
            </Descriptions>
      );

      const action = (
          <Fragment>
            <Button type="primary" onClick={handleClick}>
              <Icon type="left" />
               <FormattedMessage id="container.operation.goback" />
            </Button>
            <ButtonGroup>
              <Button onClick={() => this.handleStartScan()}>扫描</Button>
              <Button>{(detail && detail.status === 1) ? '禁用' : '解禁' }</Button>
            </ButtonGroup>
          </Fragment>
      );

      const tableVuln = (
        <Card bordered={false}>
                <div className={styles.tableListOperator}>
                {selectedRows.length > 0 && (
                  <span>
                    <Button>加入扫描白名单</Button>
                    <Button>导出成CSV</Button>
                  </span>
                )}
              </div>
               <StandardTable
                selectedRows={selectedRows}
                loading={loading}
                data={vulns}
                columns={this.columnsVuln}
                expandedRowRender={record =>                            <GridContent>
                  <Row>
                    <p style={{ margin: 0 }}>描述: {record.description}</p>
                  </Row>
                  <Row>
                    <Col xl={6}>
                      <p style={{ margin: 0 }}>CVSS2: {record.cvss2}</p>
                    </Col>
                    <Col xl={6}>
                      <p style={{ margin: 0 }}>CVSS3: {record.cvss3}</p>
                    </Col>
                    <Col xl={6}>
                      <p style={{ margin: 0 }}>所在镜像层: {record.layer}</p>
                    </Col>
                    <Col xl={6}>
                      <p style={{ margin: 0 }}>是否可忽略: {record.fixed? '是': '否'}</p>
                    </Col>
                  </Row>
                </GridContent>}
                onSelectRow={this.handleSelectRows}
                // onChange={this.handleStandardTableChange}
              />
        </Card>
      );

      const tableFiles = (
        <Card bordered={false}>
        <div className={styles.tableListOperator}>
        {selectedRows.length > 0 && (
          <span>
            <Button>加入扫描白名单</Button>
            <Button>导出成CSV</Button>
          </span>
        )}
        </div>
          <StandardTable
                  selectedRows={selectedRows}
                  loading={loading}
                  data={files}
                  columns={this.columnsFile}
                  expandedRowRender={record => <p style={{ margin: 0 }}>{record.description}</p>}
                  onSelectRow={this.handleSelectRows}
                  // onChange={this.handleStandardTableChange}

        /></Card>);

        const tableHistory = (
          <Card bordered={false}>
            <StandardTable
                    selectedRows={selectedRows}
                    loading={loading}
                    data={commands}
                    columns={this.columnsHistory}
                    onSelectRow={this.handleSelectRows}
                    // onChange={this.handleStandardTableChange}
            /></Card>);

      const tablePackages = (
          <Card bordered={false}>
            <StandardTable
                selectedRows={selectedRows}
                loading={loading}
                data={packages}
                columns={this.columnsPackages}
                onSelectRow={this.handleSelectRows}
                // onChange={this.handleStandardTableChange}
            /></Card>);

      return (
        <div>
            <PageHeaderWrapper
              title={`名称：${detail.name}`}
              extra={action}
              className={styles.pageHeader}
              content={description}
              extraContent={extra}
            >

              <Tabs defaultActiveKey="0" activeKey={currentTabKey} onChange={this.handleTabChange}>
                <TabPane tab="扫描漏洞结果" key="0">
                  {tableVuln}
                </TabPane>
                <TabPane tab="扫描文件结果" key="1">
                  {tableFiles}
                </TabPane>
                <TabPane tab="镜像文件执行命令历史" key="2">
                  {tableHistory}
                </TabPane>
                <TabPane tab="软件包信息" key="3">
                  {tablePackages}
                </TabPane>
              </Tabs>
            </PageHeaderWrapper>
            <div>
              <Modal
              title="确认"
              visible={alert}
              onOk={handleVulnOk}
              onCancel={handleVulnCancel}
            >
              <p>{`确认采用 ${fixSolution} 进行补丁?`}</p>
            </Modal>
            </div>
            <div>
            <Modal
              title="文件扫描信息"
              visible={fileDetail}
              onOk={handleFileOk}
              width={1000}
            >
              <GridContent>
                <Row>
                  <Col md={12} sm={12}>
                     <VtPie />
                  </Col>
                  <Col md={12} sm={12}>
                      <Descriptions className={styles.headerList} size="small" column={1}>
                        <Descriptions.Item label="文件类型">{fileDetailRow && fileDetailRow.cate ? fileDetailRow.cate: ''}</Descriptions.Item>
                        <Descriptions.Item label="文件SHA">{fileDetailRow && fileDetailRow.sha ? fileDetailRow.sha: ''}</Descriptions.Item>
                        <Descriptions.Item label="分析日期">{fileDetailRow && fileDetailRow.scanDate ? fileDetailRow.scanDate: ''}</Descriptions.Item>
                        <Descriptions.Item label="分析报告"><a href={(fileDetailRow && fileDetailRow.vt_lnk) ? fileDetailRow.vt_lnk: ''}> 链接 </a></Descriptions.Item>
                      </Descriptions>
                  </Col>
                </Row>
              </GridContent>
            </Modal>
            </div>
        </div>
      )
    }
}

export default ImageDetail;
