import {
  Button, Card, Descriptions, Tag,
  Col, Row, Statistic, Tooltip, Table, Divider, Modal, Input, List, Icon
} from 'antd';
import Link from 'umi/link';
import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import React, { Component, Fragment } from 'react';
import {GridContent, PageHeaderWrapper, RouteContext} from '@ant-design/pro-layout';
import { connect } from 'dva';
import numeral from 'numeral';
import { Pie, WaterWave, Gauge, TagCloud } from './components/Charts';
import ActiveChart from './components/ActiveChart';
import styles from './style.less';
import ExportJsonExcel from 'js-export-excel';

const { Search, TextArea } = Input;
const ButtonGroup = Button.Group;

function returnIcon(type) {
  return type ? ( <Icon type="check-circle" theme="twoTone" twoToneColor="#eb2f96" />):
      <Icon type="close-circle" theme="twoTone" twoToneColor="#52c41a" />
}


@connect(({ alertsAndvulnerabilities, loading }) => ({
  alertsAndvulnerabilities,
  loading: loading.models.alertsAndvulnerabilities,
}))
class Vulnerabilities extends Component {
  state = {
     displayList: undefined,
     alert: undefined,
     visible: false,
  };


  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'alertsAndvulnerabilities/fetchTags',
    });
    dispatch({
      type: 'alertsAndvulnerabilities/fetchVulns',
    });
  }

  handleFilter(list, field, value) {
    let mylist = [];
    if (field) {
      mylist = list.filter((item) => {
        return item[field] === value
      });
    } else {
      mylist = list;
    }

    this.setState({
      displayList: mylist,
    });
  }

  handleShowModal(record) {
    const description = (
          <Descriptions className={styles.headerList} size="small" column={2}>
            <Descriptions.Item label="影响模块">{record.component || ''}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{record.updated || ''}</Descriptions.Item>
            <Descriptions.Item label="CVSS2评分">{record.cvss2 || ''}</Descriptions.Item>
            <Descriptions.Item label="CVSS3评分">{record.cvss3 || ''}</Descriptions.Item>
            <Descriptions.Item label="相关镜像" span={2}>
              <List
                dataSource={record.affectImages}
                renderItem={item => <Tag color="blue"><Link to={`/detail/image/${item}`}>镜像{item}</Link></Tag>}
              />
            </Descriptions.Item>
            <Descriptions.Item label="相关容器" span={2}>
              <List
                dataSource={record.affectContainers}
                renderItem={item => <Tag color="blue"><Link to={`/detail/pod/${item}`}>容器{item}</Link></Tag>}
              />
            </Descriptions.Item>
            <Descriptions.Item label="相关主机" span={2}>
              <List
                  dataSource={record.affectHosts}
                  renderItem={item => <Tag color="blue"><Link to={`/detail/node/${item}`}>主机{item}</Link></Tag>}
              />
            </Descriptions.Item>

            <Descriptions.Item label="描述" span={2}>
              {record.description}
            </Descriptions.Item>

          </Descriptions>
    );

    const action = (
        <Fragment>
          <ButtonGroup>
            {record.inWhite?  <Button> 移除白名单 </Button> : <Button> 加入白名单 </Button>}
            {record.solved? <Button> 自动修复 </Button>: <div/>}
          </ButtonGroup>
        </Fragment>
    );

    const total = record.evalScore + '%'

    const extra = (
        <div className={styles.moreInfo}>
          {/*<Statistic title="严重度评分状态" value={['严重', '中度', '轻度', '可忽略'][record.severity || 0]} />*/}
          <li>威胁综合评分</li>
          <Pie
              animate={false}
              color="#c23219"
              percent={32}
              total={total}
              height={120}
              lineWidth={2}
          />
        </div>
    );

    const detailAttributes = (
        <Descriptions title="细节" bordered>
          <Descriptions.Item label="是否可以修复">{returnIcon(record.solved)}</Descriptions.Item>
          <Descriptions.Item label="是否存在于产品环境">{returnIcon(record.inProduction)}</Descriptions.Item>
          <Descriptions.Item label="是否网络可利用">{returnIcon(record.networkExploitable)}</Descriptions.Item>
          <Descriptions.Item label="是否可提权">{returnIcon(record.hostPrivilege)}</Descriptions.Item>
          <Descriptions.Item label="是否在三个月内发现">{returnIcon(record.criticalRecent)}</Descriptions.Item>
        </Descriptions>
    )

    const alert = (
      <Fragment>
        <PageHeaderWrapper
            title={`名称：${record.name}`}
            extra={action}
            className={styles.pageHeader}
            content={description}
            extraContent={extra}
        >
          {detailAttributes}
        </PageHeaderWrapper>
      </Fragment>
    );

    this.setState({
      alert,
      visible: true,
    })
  }

  handleModalOk() {
    this.setState({
      alert: null,
      visible : false,
    });
  }

  handleModalCancel() {
    this.setState({
      alert: null,
      visible : false,
    });
  }

  hanldeExport() {
    const {
      alertsAndvulnerabilities: { vulns, },
    } = this.props;
    const displayList = (this.state.displayList) ? this.state.displayList: vulns;
    if (displayList && displayList.length > 0) {
      let option = {};
      option.fileName = '漏洞信息';
      option.datas = [
        {
          sheetData: displayList,
          sheetName: 'vulnerabilities',
        },
      ];

      const toExcel = new ExportJsonExcel(option);
      toExcel.saveExcel();
    } else {
      alert('列表为空');
    }
  }

  render() {
    const {
      alertsAndvulnerabilities: { vulns, tags },
      loading,
    } = this.props;

    const { alert, visible } = this.state;
    const handleModalOk = this.handleModalOk.bind(this);
    const handleModalCancel = this.handleModalCancel.bind(this);
    const handleShowModal = this.handleShowModal.bind(this);
    const hanldeExport = this.hanldeExport.bind(this);

    const columns = [
      {
        title: '漏洞名',
        dataIndex: 'name',
        key: 'name',
        render: (text, record) => (
            <a href={record.lnk}>{record.name}</a>
        ),
      },
      {
        title: '影响模块',
        dataIndex: 'component',
      }, {
        title: '严重度',
        dataIndex: 'severity',
        render(val) {
          return ['严重', '中度', '轻度', '可忽略'][val || 0]
        },
      },
      {
        title: '最近更新',
        dataIndex: 'updated',
      },
      {
        title: '操作',
        render: (text, record) => (
          <Fragment>
            <a onClick={() => handleShowModal(record)}> 查看漏洞细节 </a>
          </Fragment>
        ),
      },
    ];

    const displayList = this.state.displayList ? this.state.displayList : vulns;
    console.log(this.state.displayList);
    return (
      <GridContent>

        <React.Fragment>
          <Row gutter={24}>
            <Col
              xl={18}
              lg={24}
              md={24}
              sm={24}
              xs={24}
              style={{
                marginBottom: 24,
              }}
            >
              <Card
                title={
                  <FormattedMessage
                    id="alertsandvulnerabilities.monitor.trading-activity"
                    defaultMessage="CVE Statistics"
                  />
                }
                bordered={false}
              >
                <Row>
                  <Col md={6} sm={12} xs={24}>
                    <a onClick={() => { this.handleFilter(vulns, null, null)}} >
                    <Statistic
                      title={
                        <FormattedMessage
                          id="alertsandvulnerabilities.monitor.total-transactions"
                          defaultMessage="Total transactions today"
                        />
                      }
                      value={numeral(133).format('0,0')}
                    />
                    </a>
                  </Col>
                  <Col md={6} sm={12} xs={24}>
                    <a onClick={() => { this.handleFilter(vulns, 'recent', 0)}} >
                    <Statistic
                      title={
                        <FormattedMessage
                          id="alertsandvulnerabilities.monitor.sales-target"
                          defaultMessage="Sales target completion rate"
                        />
                      }
                      value="92"
                    />
                    </a>
                  </Col>
                  <Col md={6} sm={12} xs={24}>
                    <a onClick={() => { this.handleFilter(vulns, 'solved', true)}} >
                    <Statistic
                      title={
                        <FormattedMessage
                          id="alertsandvulnerabilities.monitor.remaining-time"
                          defaultMessage="Remaining time of activity"
                        />
                      }
                      value="36"
                    />
                    </a>
                  </Col>
                  <Col md={6} sm={12} xs={24}>
                    <a onClick={() => { this.handleFilter(vulns, 'severity', 0)}} >
                    <Statistic
                      title={
                        <FormattedMessage
                          id="alertsandvulnerabilities.monitor.total-transactions-per-second"
                          defaultMessage="Total transactions per second"
                        />
                      }
                      value={numeral(64).format('0,0')}
                    />
                    </a>
                  </Col>
                </Row>
              </Card>

              <Card
                title={
                  <FormattedMessage
                    id="alertsandvulnerabilities.monitor.proportion-per-category"
                    defaultMessage="Proportion Per Category"
                  />
                }
                bordered={false}
                className={styles.pieCard}
              >
                <Row
                  style={{
                    padding: '16px 0',
                  }}
                >
                  <Col span={6}>
                    <div>
                      <ul className={styles.legend}>
                      <a onClick={() => { this.handleFilter(vulns, 'networkExploitable', true)}} >
                      <li><FormattedMessage
                          id="alertsandvulnerabilities.monitor.fast-food"
                          defaultMessage="Fast food"
                        /></li>
                      </a>
                      </ul>
                    </div>
                    <Pie
                      animate={false}
                      color="#2FC25B"
                      percent={28}
                      total="28%"
                      height={120}
                      lineWidth={2}
                    />
                  </Col>
                  <Col span={6}>
                    <div>
                      <ul className={styles.legend}>
                      <a onClick={() => { this.handleFilter(vulns, 'hostPrivilege', true)}} >
                      <li><FormattedMessage
                          id="alertsandvulnerabilities.monitor.western-food"
                          defaultMessage="Western food"
                        /></li>
                      </a>
                      </ul>
                    </div>
                    <Pie
                      animate={false}
                      color="#5DDECF"
                      percent={22}
                      total="22%"
                      height={120}
                      lineWidth={2}
                    />
                  </Col>
                  <Col span={6}>
                    <ul className={styles.legend}>
                      <a onClick={() => { this.handleFilter(vulns, 'criticalRecent', true)}} >
                      <li><FormattedMessage
                          id="alertsandvulnerabilities.monitor.hot-pot"
                          defaultMessage="Hot pot"
                        /></li>
                      </a>
                      </ul>

                    <Pie
                      animate={false}
                      color="#2FC25B"
                      percent={32}
                      total="32%"
                      height={120}
                      lineWidth={2}
                    />
                  </Col>
                  <Col span={6}>
                    <ul className={styles.legend}>
                      <a onClick={() => { this.handleFilter(vulns, 'inProduction', true)}} >
                      <li>生产环境中漏洞</li>
                      </a>
                      </ul>
                    <Pie
                      animate={false}
                      color="#c23219"
                      percent={32}
                      total="46%"
                      height={120}
                      lineWidth={2}
                    />
                  </Col>
                </Row>
              </Card>

              <Card>
                <div>
                  <Search
                    placeholder="输入CVE号"
                    enterButton="搜索"
                    style={{ width: 400 }}
                    onSearch={(value) => { this.handleFilter(vulns, 'name', value)}}
                  />
                  <Divider type="vertical" />
                  <Button type="primary" onClick={()=>{this.handleFilter(vulns, null, null)}}> 清空 </Button>
                  <Divider type="vertical" />

                  <Button type="primary" shape="round" icon="download" onClick={() => {hanldeExport()}} />
                </div>
                <div className={styles.standardTable}>
                  <Table
                    columns={columns}
                    dataSource={displayList}
                    expandedRowRender={
                       record =>
                         <div>
                           <GridContent>
                             <Row>
                               <p style={{ margin: 0 }}>{record.description}</p>
                             </Row>
                             <Row>
                               <Col xl={6}>
                                 <p style={{ margin: 0 }}>网络可利用: {record.networkExploitable? '是': '否'}</p>
                               </Col>
                               <Col xl={6}>
                                 <p style={{ margin: 0 }}>主机可提权: {record.hostPrivilege? '是': '否'}</p>
                               </Col>
                               <Col xl={6}>
                                 <p style={{ margin: 0 }}>最近发掘: {record.criticalRecent? '是': '否'}</p>
                               </Col>
                               <Col xl={6}>
                                 <p style={{ margin: 0 }}>是否用于生产: {record.inProduction? '是': '否'}</p>
                               </Col>
                             </Row>
                           </GridContent>
                         </div>
                     }
                  />
                </div>
              </Card>
            </Col>
            <Col
              xl={6}
              lg={12}
              sm={24}
              xs={24}
              style={{
                marginBottom: 24,
              }}
            >
              <Card
                title={
                  <FormattedMessage q
                    id="alertsandvulnerabilities.monitor.activity-forecast"
                    defaultMessage="Activity forecast"
                  />
                }
                style={{
                  marginBottom: 24,
                }}
                bordered={false}
              >
                <ActiveChart />
              </Card>

              <Card
                title={
                  <FormattedMessage
                    id="alertsandvulnerabilities.monitor.popular-searches"
                    defaultMessage="Popular Searches"
                  />
                }
                loading={loading}
                bordered={false}
                bodyStyle={{
                  overflow: 'hidden',
                }}
              >
                <TagCloud data={tags || []} height={320} />
              </Card>

              <Card
                title={
                  <FormattedMessage
                    id="alertsandvulnerabilities.monitor.resource-surplus"
                    defaultMessage="Resource Surplus"
                  />
                }
                bodyStyle={{
                  textAlign: 'center',
                  fontSize: 0,
                }}
                bordered={false}
              >
                <WaterWave
                  height={200}
                  title={
                    <FormattedMessage
                      id="alertsandvulnerabilities.monitor.fund-surplus"
                      defaultMessage="Fund Surplus"
                    />
                  }
                  percent={34}
                />
              </Card>

            </Col>
          </Row>
        </React.Fragment>
          <Modal
            visible={visible}
            closable={false}
            width={1200}
            onOk={() => handleModalOk()}
            onCancel={() => handleModalCancel()}
            okText="关闭"
            cancelText="取消"
          >
          {alert}
          </Modal>
      </GridContent>
    );
  }
}

export default Vulnerabilities;
