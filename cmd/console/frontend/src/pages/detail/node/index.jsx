// import { Card, Col, Form, List, Row, Select, Typography } from 'antd';
import {
  Badge,
  Button,
  Card,
  Input,
  Statistic,
  Descriptions,
  Divider,
  Dropdown,
  Icon,
  Menu,
  Popover,
  Steps,
  Table,
  Tabs,
  Tag,
  Row,
  Col,
  Tooltip,
  Empty, Modal, Progress,
} from 'antd';

import Link from 'umi/link';
import { GridContent, PageHeaderWrapper, RouteContext } from '@ant-design/pro-layout';
import React, { Component, Fragment } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import CalendarHeatmap from './components/CalendarHeatmap';
import ComplianceTable from './components/ComplianceTable';
import styles from './style.less';
import {List} from "antd/lib/list";

const { TextArea } = Input;
const ButtonGroup = Button.Group;
const { TabPane } = Tabs;

const severities = ['#cc0b23', '#c9830e', '#25ce8b'];
const statusMap = ['error', 'warning', 'default'];
const labels = ['含严重问题', '警告', '正常'];
const severitiesText = ['严重', '中等', '轻度'];
const statusText = ['异常', '终止', '运行中'];
const resultsText = ['通过', '失败'];
const resultStatusMap = ['default', 'error'];

const columns = [
  {
    title: '项目',
    dataIndex: 'name',
    key: 'key',
  },
  {
    title: '严重度',
    render: (text, record) => (
      <div>
      <Icon type="bulb" style={{ color: severities[record.severity]}} theme="filled"/>
        {severitiesText[record.severity]}
      </div>
    ),
  },
  {
    title: '描述',
    dataIndex: 'description',
  },
  {
    title: '时间',
    dataIndex: 'created',
  },
];

let timer = null;

@connect(({ node: { detail, logs, alerts, reports, containers }, loading }) => ({
  detail,
  logs,
  reports,
  containers,
  detailLoad: loading.effects['node/fetchDetail'],
  logLoading: loading.effects['node/fetchLog'],
  reportLoading: loading.effects['node/fetchReport'],
  containerLoading: loading.effects['node/fetchContainer']
}))

class NodeDetail extends Component {
    state = {
      tabActiveKey: 'Report',
      alert: (<TextArea />),
      visible: false,
      visibleScan: true,
      scanProgress: 0,
    };

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    progress() {
      const value = this.state.scanProgress + 1;
      this.setState({
        scanProgress: value,
      })

      if (value >= 100) {
        this.setState({
          scanProgress: 100,
          visibleScan: true
        });
        clearInterval(timer);
      }
    }

    handleStartScan() {
      this.setState({
        scanProgress: 0,
        visibleScan: false
      })
      timer = setInterval(this.progress.bind(this), 500);
    }

    componentDidMount() {
      const { dispatch } = this.props;
      dispatch({
        type: 'node/fetchDetail',
        payload: this.props.match.params.container || 0,
      });
      dispatch({
        type: `node/fetchLog`,
        payload: {
          vulns: 2,
          date: '2019-11-28'
        },
      });

      dispatch({
        type: `node/fetchReport`,
        payload: this.props.match.params.container || 0,
      });

      dispatch({
        type: `node/fetchContainer`,
        payload: this.props.match.params.container || 0,
      })
    }

    onEventClick = time => {
      const { dispatch } = this.props;

      dispatch({
        type: 'node/fetchLog',
        payload: time,
      })
    };

    handleShowModal(record) {
      const alert = <TextArea disabled autoSize defaultValue={record} value={record}/>;
      console.log(record);
      this.setState({
        alert,
        visible: true,
      })
    }

    handleModalCancel() {
        this.setState({
          visible: false,
        })
    }

    render() {
      const {
        detail,
        logs,
        reports,
        containers,
        logLoading,
        reportLoading,
        containerLoading,
      } = this.props;

      const { visible, alert, scanProgress, visibleScan } = this.state;
      const handleShowModal = this.handleShowModal.bind(this);
      const handleModalCancel = this.handleModalCancel.bind(this);
      const reportColumns = [
        {
          title: '检查类型',
          dataIndex: 'category',
        },
        {
          title: '描述',
          dataIndex: 'test',
        },
        {
          title: '结果',
          render: (text, record) => (
              <div>
                <Badge status={resultStatusMap[record.result]} text={resultsText[record.result]} />
              </div>
          ),
        },
        {
          title: '操作',
          render: (text, record) => (
              <Fragment>
                {
                  (record.result === 0) ? null: (<a onClick={() => handleShowModal(record.remediation)}> 查看治理方案 </a>)
                }
              </Fragment>
          ),
        },

      ];
      const containerColumns = [
        {
          title: '名称',
          dataIndex: 'name',
        },
        {
          title: '镜像',
          dataIndex: 'image',
        },
        {
          title: '上次更新',
          dataIndex: 'updatedAt',
        },
        {
          title: '状态',
          render: (text, record) => (
              <div>
                <Badge status={statusMap[record.status]} text={statusText[record.status]} />
              </div>
          ),
        },
        {
          title: '操作',
          render: (text, record) => (
              <Fragment>
                <Link to={`/detail/pod/${record.key}`}> 查看细节 </Link>
              </Fragment>
          ),
        },

      ];

      const handleClick = this.handleClick.bind(this);
      const eventClick = this.onEventClick.bind(this);

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
      </span>);
      const description = (<RouteContext.Consumer>
          {({ isMobile }) => (
            <Descriptions className={styles.headerList} size="small" column={2}>
              <Descriptions.Item label="操作系统及版本"> {detail.os}</Descriptions.Item>
              <Descriptions.Item label="内核版本"> {detail.kernel}</Descriptions.Item>
              <Descriptions.Item label="更新时间">{detail.updated}</Descriptions.Item>
              <Descriptions.Item label="标签">{tags}</Descriptions.Item>
              <Descriptions.Item label="状态"> <Badge status={statusMap[detail.status]} text={labels[detail.status]} /> </Descriptions.Item>
            </Descriptions>
          )}
        </RouteContext.Consumer>);
      const action = (<Fragment>
            <Button type="primary" onClick={handleClick}>
              <Icon type="left" />
               <FormattedMessage id="container.operation.goback" />
            </Button>
            <ButtonGroup>
              <Button disabled={!visibleScan} onClick={() => this.handleStartScan()}>运行合规检查</Button>
            </ButtonGroup>
            { visibleScan ? (<div/>): (<div><Progress percent={scanProgress}/></div>)}
          </Fragment>);
      const contentList = {
        Log: (
          <Table
            pagination={false}
            loading={logLoading}
            dataSource={logs}
            columns={columns}
          />
        ),
        Report: (
          <Table
            pagination={false}
            loading={reportLoading}
            dataSource={reports}
            columns={reportColumns}
          />
        ),
        Container: (
            <Table
                pagination={false}
                loading={containerLoading}
                dataSource={containers}
                columns={containerColumns}
            />
        )
      };

      return (
        <div>
            <Modal title={'查看治理方案'}
                   width={800}
                   visible={visible}
                   onOk={handleModalCancel}
                   onCancel={handleModalCancel}
            >
              {alert}
            </Modal>
            <PageHeaderWrapper
              title={`名称：${detail.name}`}
              extra={action}
              className={styles.pageHeader}
              content={description}
            >
            <div className={styles.main}>
              <Tabs defaultActiveKey="1">
                <TabPane tab="安全事件" key="1">
                  <GridContent>
                    <Card>
                      相关安全事件热点图
                    </Card>
                    <Card>
                      {<CalendarHeatmap eventClick={eventClick}/>}
                    </Card>
                    <Card>
                      {contentList.Log}
                    </Card>
                  </GridContent>
                </TabPane>
                <TabPane tab="主机合规检查" key="2">
                  <Card>
                  <ComplianceTable />
                  </Card>
                  <GridContent>
                    {contentList.Report}
                  </GridContent>
                </TabPane>
                <TabPane tab="负载容器" key="3">
                  <GridContent>
                    {contentList.Container}
                  </GridContent>
                </TabPane>
              </Tabs>

              {/* <Card */}
                {/* className={styles.tabsCard} */}
                {/* bordered={false} */}
                {/* tabList={operationTabList} */}
                {/* onTabChange={this.onTabChange} */}
              {/* > */}

              {/* </Card> */}

              {/* <GridContent> */}
                {/* <Row gutter={24}> */}
                  {/* <Col xl={12} lg={24} md={24} sm={24} xs={24}> */}
                    {/* <Card> 告警热点图 </Card> */}
                  {/* </Col> */}
                  {/* <Col xl={12} lg={24} md={24} sm={24} xs={24}> */}
                    {/* <Card> 相关漏洞热点图 </Card> */}
                  {/* </Col> */}
                {/* </Row> */}
                {/* <Row gutter={24}> */}
                 {/* <Col xl={12} lg={24} md={24} sm={24} xs={24}> */}
                  {/* <Card> */}
                  {/* <CalendarHeatmap /> */}
                  {/* </Card> */}
                {/* </Col> */}
                {/* <Col xl={12} lg={24} md={24} sm={24} xs={24}> */}
                {/* <Card> */}
                  {/* <CalendarHeatmap /> */}
                {/* </Card> */}
                {/* </Col> */}
              {/* </Row> */}
             {/* </GridContent> */}
              {/* <GridContent> */}
              {/* <Card */}
                {/* className={styles.tabsCard} */}
                {/* bordered={false} */}
                {/* tabList={operationTabList} */}
                {/* onTabChange={this.onTabChange} */}
              {/* > */}
              {/* {contentList[tabActiveKey]} */}
              {/* </Card> */}
              {/* </GridContent> */}
            </div>
            </PageHeaderWrapper>
        </div>
      )
    }
}

export default NodeDetail;
