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
  Popover,
  Steps,
  Table,
  Tag,
  Row,
  Col,
  Tooltip,
  Empty,
} from 'antd';
import Link from 'umi/link';
import { GridContent, PageHeaderWrapper, RouteContext } from '@ant-design/pro-layout';
import React, { Component, Fragment } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import CalendarHeatmap from './components/CalendarHeatmap';

import styles from './style.less';

const { Step } = Steps;
const ButtonGroup = Button.Group;

const status = ['停止', '运行中', '已完成', '异常'];

const operationTabList = [
  {
    key: 'Alert',
    tab: '相关告警',
  },
  {
    key: 'Report',
    tab: '相关合规',
  },
  {
    key: 'Log',
    tab: '相关日志',
  },
];

const columns = [
  {
    title: '项目',
    dataIndex: 'name',
    key: 'name',
  },
  {
    title: '时间',
    dataIndex: 'created',
    key: 'created',
  },
];


@connect(({ container: { detail, logs, alerts, reports }, loading }) => ({
  detail,
  logs,
  alerts,
  reports,
  detailLoad: loading.effects['container/fetchDetail'],
  logLoading: loading.effects['container/fetchLog'],
  reportLoading: loading.effects['container/fetchReport'],
  alertLoading: loading.effects['container/fetchAlert'],
}))

class ContainerDetail extends Component {
    state = {
      tabActiveKey: 'Alert',
    };

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    componentDidMount() {
      const { dispatch } = this.props;
      dispatch({
        type: 'container/fetchDetail',
        payload: this.props.match.params.container || 0,
      });
      dispatch({
        type: `container/fetch${this.state.tabActiveKey}`,
        payload: this.props.match.params.container || 0,
      });
    }

    onTabChange = tabActiveKey => {
      const { dispatch } = this.props;
      this.setState({
        tabActiveKey,
      });

      dispatch({
        type: `container/fetch${tabActiveKey}`,
        payload: this.props.match.params.container || 0,
      });
    };

    render() {
      const { tabActiveKey } = this.state;

      const {
        detail,
        logs,
        alerts,
        reports,
        detailLoad,
        logLoading,
        reportLoading,
        alertLoading,
      } = this.props;

      const handleClick = this.handleClick.bind(this);

      const extra = (
        <div className={styles.moreInfo}>
          <Statistic title="状态" value={status[detail.status || 0]} />
          <Statistic title="相关告警数" value={detail.total} />
        </div>
      );

      const imageId = detail.image && detail.image.key ? detail.image.key: '';
      const imageName = detail.image && detail.image.name ? detail.image.name: '';
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
        <RouteContext.Consumer>
          {({ isMobile }) => (
            <Descriptions className={styles.headerList} size="small" column={2}>
              <Descriptions.Item label="创建人">{detail.owner || ''}</Descriptions.Item>
              <Descriptions.Item label="命名空间">{detail.namespace || ''}</Descriptions.Item>
              <Descriptions.Item label="创建时间">{detail.created || ''}</Descriptions.Item>
              <Descriptions.Item label="镜像">
                <Link to={`/detail/image/${imageId}`}>{imageName}</Link>
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">{detail.updated}</Descriptions.Item>
              <Descriptions.Item label="标签">{tags}</Descriptions.Item>
            </Descriptions>
          )}
        </RouteContext.Consumer>
      );

      const action = (
          <Fragment>
            <Button type="primary" onClick={handleClick}>
              <Icon type="left" />
               <FormattedMessage id="container.operation.goback" />
            </Button>
            <ButtonGroup>
              <Button>取证</Button>
              <Button>网络隔离</Button>
              <Button>停止</Button>
            </ButtonGroup>

          </Fragment>
      );

      const contentList = {
        Alert: (
          <Table
            pagination={false}
            loading={alertLoading}
            dataSource={alerts}
            columns={columns}
          />
        ),
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
            columns={columns}
          />
        ),
      };

      return (
        <div>
            <PageHeaderWrapper
              title={`名称：${detail.name}`}
              extra={action}
              className={styles.pageHeader}
              content={description}
              extraContent={extra}
            >
            <div className={styles.main}>
              <GridContent>
                <Card>
                  相关漏洞热点图
                </Card>
                  <Card>
                    {<CalendarHeatmap />}
                  </Card>
              </GridContent>
              {/*<GridContent>*/}
                {/*<Row gutter={24}>*/}
                  {/*<Col xl={12} lg={24} md={24} sm={24} xs={24}>*/}
                    {/*<Card> 告警热点图 </Card>*/}
                  {/*</Col>*/}
                  {/*<Col xl={12} lg={24} md={24} sm={24} xs={24}>*/}
                    {/*<Card> 相关漏洞热点图 </Card>*/}
                  {/*</Col>*/}
                {/*</Row>*/}
                {/*<Row gutter={24}>*/}
                 {/*<Col xl={12} lg={24} md={24} sm={24} xs={24}>*/}
                  {/*<Card>*/}
                  {/*<CalendarHeatmap />*/}
                  {/*</Card>*/}
                {/*</Col>*/}
                {/*<Col xl={12} lg={24} md={24} sm={24} xs={24}>*/}
                {/*<Card>*/}
                  {/*<CalendarHeatmap />*/}
                {/*</Card>*/}
                {/*</Col>*/}
              {/*</Row>*/}
             {/*</GridContent>*/}
              <GridContent>
              <Card
                className={styles.tabsCard}
                bordered={false}
                tabList={operationTabList}
                onTabChange={this.onTabChange}
              >
              {contentList[tabActiveKey]}
              </Card>
              </GridContent>
            </div>
            </PageHeaderWrapper>
        </div>
      )
    }
}

export default ContainerDetail;
