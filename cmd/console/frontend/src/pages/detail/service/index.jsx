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

import styles from './style.less';
import IpMap from "./components/IpMap";

const { Step } = Steps;
const ButtonGroup = Button.Group;

const status = ['停止', '运行中', '已完成', '异常'];

const operationTabList = [
  {
    key: 'Inbound',
    tab: '今日进入流量源地址分布',
  },
  {
    key: 'Outbound',
    tab: '今日向外流量源地址分布',
  },
];


@connect(({ service: { detail, inbound, outbound }, loading }) => ({
  detail,
  inbound,
  outbound,
  detailLoad: loading.effects['service/fetchDetail'],
  inLoading: loading.effects['service/fetchInbound'],
  outLoading: loading.effects['service/fetchOutbound'],
}))

class ServiceDetail extends Component {
    state = {
      tabActiveKey: 'Inbound',
    };

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    componentDidMount() {
      const { dispatch } = this.props;
      dispatch({
        type: 'service/fetchDetail',
        payload: this.props.match.params.service || 0,
      });
      dispatch({
        type: `service/fetch${this.state.tabActiveKey}`,
        payload: this.props.match.params.service || 0,
      });
    }

    onTabChange = tabActiveKey => {
      const { dispatch } = this.props;
      this.setState({
        tabActiveKey,
      });

      dispatch({
        type: `service/fetch${tabActiveKey}`,
        payload: this.props.match.params.service || 0,
      });
    };

    render() {
      const { tabActiveKey } = this.state;

      const {
        detail,
        inbound,
        outbound,
      } = this.props;

      const handleClick = this.handleClick.bind(this);
      const extra = (
        <div className={styles.moreInfo}>
          <Statistic title="状态" value={status[detail.status || 0]} />
          <Statistic title="相关网络告警数" value={detail.total} />
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
      </span>);
      const description = (
          <Descriptions className={styles.headerList} size="small" column={2}>
            <Descriptions.Item label="创建人">{detail.owner || ''}</Descriptions.Item>
            <Descriptions.Item label="命名空间">{detail.namespace || ''}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{detail.created || ''}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{detail.updated}</Descriptions.Item>
            <Descriptions.Item label="标签">{tags}</Descriptions.Item>
          </Descriptions>
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
        Inbound: (
            <IpMap markers={inbound}/>
        ),
        Outbound: (
            <IpMap markers={outbound}/>
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

export default ServiceDetail;
