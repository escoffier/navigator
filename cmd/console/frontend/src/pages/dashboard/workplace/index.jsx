import { Avatar, Card, Col, List, Skeleton, Row, Statistic } from 'antd';
import React, { Component } from 'react';
import Link from 'umi/link';
import { PageHeaderWrapper } from '@ant-design/pro-layout';
import { connect } from 'dva';
import moment from 'moment';
import router from 'umi/router';
import Radar from './components/Radar';
import EditableLinkGroup from './components/EditableLinkGroup';
import styles from './style.less';
import notices from './fillData';


const links = [
  {
    title: '查看今日报警',
    href: '/alerts/overview',
  },
  {
    title: '查看漏洞',
    href: '/alerts/vulnerabilities',
  },
  {
    title: '查看今日日志',
    href: '/logs/general',
  },
  {
    title: '生成统计报表',
    href: '/logs/general',
  },
  {
    title: '添加安全策略',
    href: '/detail/rule/add',
  },
  {
    title: '添加新代理',
    href: '/settings/agent',
  },
];

const PageHeaderContent = ({ currentUser }) => {
  const loading = currentUser && Object.keys(currentUser).length;

  if (!loading) {
    return (
      <Skeleton
        avatar
        paragraph={{
          rows: 1,
        }}
        active
      />
    );
  }

  return (
    <div className={styles.pageHeaderContent}>
      <div className={styles.avatar}>
        <Avatar size="large" src={currentUser.avatar} />
      </div>
      <div className={styles.content}>
        <div className={styles.contentTitle}>
          早安，
          {currentUser.name}
        </div>
        <div>
          {currentUser.title} |{currentUser.group}
        </div>
      </div>
    </div>
  );
};

const ExtraContent = ({ stat }) => (
  <div className={styles.extraContent}>

    <div className={styles.statItem}>
      <Link to="/assets/tablelist">
        <Statistic title="主机数" value={stat.nodes ? stat.nodes.total: 0} />
      </Link>
    </div>
    <div className={styles.statItem}>
      <Link to="/assets/images">
      <Statistic title="镜像" value={stat.images ? stat.images.inUse : 0} suffix={'/' + (stat.images ? stat.images.total: 0)} />
      </Link>
    </div>
    <div className={styles.statItem}>
      <Link to="/assets/cluster">
      <Statistic title="微服务" value={stat.services ? stat.services.total: 0} />
      </Link>
    </div>
    <div className={styles.statItem}>
      <Link to="/assets/tablelist">
      <Statistic title="容器数" value={stat.containers ? stat.containers.total: 0} />
      </Link>
    </div>
    <div className={styles.statItem} >
      <Link to="/assets/tablelist">
      <Statistic title="代理总数" value={stat.agents ? stat.agents.total: 0} />
      </Link>
    </div>
  </div>
);

@connect(
  ({
    dashboardAndworkplace: { currentUser, projectNotice, activities, radarData, statData }, loading }) => ({
    currentUser,
    projectNotice,
    activities,
    radarData,
    statData,
    currentUserLoading: loading.effects['dashboardAndworkplace/fetchUserCurrent'],
    projectLoading: loading.effects['dashboardAndworkplace/fetchProjectNotice'],
    activitiesLoading: loading.effects['dashboardAndworkplace/fetchActivitiesList'],
  }),
)


class Workplace extends Component {
  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'dashboardAndworkplace/init',
    });
  }

  componentWillUnmount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'dashboardAndworkplace/clear',
    });
  }

  renderActivities = item => {
    const events = item.template.split(/@\{([^{}]*)\}/gi).map(key => {
      if (item[key]) {
        return (
          <Link to={item[key].link}>
            {item[key].name}
          </Link>
        );
      }

      return key;
    });
    return (
      <List.Item key={item.id}>
        <List.Item.Meta
          avatar={<Avatar src={item.severity.avatar} />}
          title={
            <span>
              <a className={styles.username}>{item.user.name}</a>
              &nbsp;
              <span className={styles.event}>{events}</span>
            </span>
          }
          description={
            <span className={styles.datetime} title={item.updatedAt}>
              {moment(item.updatedAt).fromNow()}
            </span>
          }
        />
      </List.Item>
    );
  };

  handleClick(link, cate) {
    router.push({
      pathname: link,
      fillData: {
        cate,
      },
    });
  }

  render() {
    const {
      currentUser,
      activities,
      projectNotice,
      projectLoading,
      activitiesLoading,
      radarData,
      statData,
    } = this.props;
    const handleClick  = this.handleClick.bind(this);
    return (
      <PageHeaderWrapper
        content={<PageHeaderContent currentUser={currentUser} />}
        extraContent={<ExtraContent stat={statData? statData: {}}/>}
      >
        <Row gutter={24}>
          <Col xl={16} lg={24} md={24} sm={24} xs={24}>
            <Card
              className={styles.projectList}
              style={{
                marginBottom: 24,
              }}
              title="管理安全任务"
              bordered={false}
              extra={<Link to="/">全部任务</Link>}
              loading={projectLoading}
              bodyStyle={{
                padding: 0,
              }}
            >
              {projectNotice.map(item => (
                <Card.Grid className={styles.projectGrid} key={item.id}>
                  <Card
                    bodyStyle={{
                      padding: 0,
                    }}
                    bordered={false}
                  >
                    <Card.Meta
                      title={
                        <div className={styles.cardTitle}>
                          <Avatar size="small" src={item.logo} />
                          <a onClick={() => handleClick(item.href, item.cate)}>{item.title}</a>
                        </div>
                      }
                      description={item.description}
                    />
                    <div className={styles.projectItemContent}>
                      <Link to={item.memberLink}>{item.member || ''}</Link>
                      {item.updatedAt && (
                        <span className={styles.datetime} title={item.updatedAt}>
                          {moment(item.updatedAt).fromNow()}
                        </span>
                      )}
                    </div>
                  </Card>
                </Card.Grid>
              ))}
            </Card>
            <Card
              bodyStyle={{
                padding: 0,
              }}
              bordered={false}
              className={styles.activeCard}
              title="安全动态"
              loading={activitiesLoading}
            >
              <List
                loading={activitiesLoading}
                renderItem={item => this.renderActivities(item)}
                dataSource={activities}
                className={styles.activitiesList}
                size="large"
              />
            </Card>
          </Col>
          <Col xl={8} lg={24} md={24} sm={24} xs={24}>
            <Card
              style={{
                marginBottom: 24,
              }}
              title="快速开始"
              bordered={false}
              bodyStyle={{
                padding: 0,
              }}
            >

            <EditableLinkGroup onAdd={() => {}} links={links} linkElement={Link} />
            </Card>
            <Card
              style={{
                marginBottom: 24,
              }}
              bordered={false}
              title="威胁指数"
              loading={radarData? radarData.length === 0: true}
            >
              <div className={styles.chart}>
                <Radar hasLegend height={343} data={radarData} />
              </div>
            </Card>
            <Card
              bodyStyle={{
                paddingTop: 12,
                paddingBottom: 12,
              }}
              bordered={false}
              title="快速链接"
            >
              <div className={styles.members}>
                <Row gutter={48}>
                  {notices.map(item => (
                    <Col span={12} key={`members-item-${item.id}`}>
                      <Link to={item.href}>
                        <Avatar src={item.logo} size="small" />
                        <span className={styles.member}>{item.member}</span>
                      </Link>
                    </Col>
                  ))}
                </Row>
              </div>
            </Card>

          </Col>
        </Row>
      </PageHeaderWrapper>
    );
  }
}

export default Workplace;
