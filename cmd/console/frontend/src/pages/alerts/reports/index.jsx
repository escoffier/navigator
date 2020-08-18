import {
  Button, Card, Tag,
  Col, Row, Statistic, Tooltip, Table, Divider, Modal, Input, List, Tabs, Badge, Icon
} from 'antd';
import Link from 'umi/link';
import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import React, { Component, Fragment } from 'react';
import { GridContent } from '@ant-design/pro-layout';
import { connect } from 'dva';
import numeral from 'numeral';
import ExportJsonExcel from 'js-export-excel';
import {Descriptions} from "antd/lib/descriptions";
import styles from "../vulnerabilities/style.less";

const { TabPane } = Tabs;
const { TextArea } = Input;

@connect(({ alertsAndreports, loading }) => ({
  alertsAndreports,
  loading: loading.models.alertsAndreports,
}))
class Reports extends Component {
  state = {
     displayList: undefined,
     alert: undefined,
     visible: false,
  };


  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'alertsAndreports/fetchReports',
    });

    dispatch({
      type: 'alertsAndreports/fetchReportProblems',
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

  handleShowModal(type, record) {
    let alert = null;

    if ( type === 'whitelist') {
      alert = (<p>{`确认加${record.name}入白名单?`}</p>)
    } else if ( type === 'container' ) {
      alert = (<div>确定已读？</div>);
    } else if ( type === 'handle') {
        alert = (<TextArea rows={25} placeholder={record.handle}/>)
    }

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

  handleExport() {
    const {
      alertsAndreports: { reports, },
    } = this.props;
    const displayList = (this.state.displayList) ? this.state.displayList: reports;
    if (displayList && displayList.length > 0) {
      let option = {};
      option.fileName = '扫描报告';
      option.datas = [
        {
          sheetData: displayList,
          sheetName: 'reports',
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
      alertsAndreports: { reports, problems, },
      loading,
    } = this.props;

    const { alert, visible } = this.state;
    const handleModalOk = this.handleModalOk.bind(this);
    const handleModalCancel = this.handleModalCancel.bind(this);
    const handleShowModal = this.handleShowModal.bind(this);
    const displayList = (this.state.displayList) ? this.state.displayList: reports;

    const columns = [
      {
        title: '扫描类型',
        dataIndex: 'name',
        key: 'name',
        render: (text, record) => (
            <Link to={`/detail/report/${record.key}`}>{record.name}</Link>
        ),
      },
      {
        title: '问题总数',
        dataIndex: 'total',
      },
      {
        title: '严重问题数',
        dataIndex: 'critical',
      },
      {
        title: '结果评分',
        dataIndex: 'severity',
        render(val) {
           return <Badge status={['error', 'warning', 'default', 'success'][val]} text={['严重', '中度', '轻度', '可忽略'][val]} />
        },
      },
      {
        title: '开始时间',
        dataIndex: 'created',
      },
      {
        title: '完成时间',
        dataIndex: 'finished',
      },
      {
        title: '操作',
        render: (text, record) => (
          <Fragment>
            <a onClick={() => handleShowModal('container', record)}> 标记为已读 </a>
          </Fragment>
        ),
      },
    ];

    const problemColumns = [
      {
        title: '问题类型',
        dataIndex: 'name',
      },
      {
        title: '描述',
        dataIndex: 'description',

      },
      {
        title: '存在问题实体数',
        render: (text, record) => {
          return <div> {record.complianceHost.length} </div>
        }
      },
      {
        title: '实体',
        render: (text, record) => {
          return   <List
              dataSource={record.complianceHost}
              renderItem={item => <Tag color="blue"> <Link to={item.lnk}>{item.name} </Link></Tag>}
          />
        }
      },
      {
        title: '严重度',
        dataIndex: 'critical',
        render(val) {
          return <Badge status={['error', 'warning', 'success'][val]} text={['严重', '中度', '轻度'][val]} />
        }
      },
      {
        title: '操作',
        render: (text, record) => (
            <Fragment>
              <a onClick={() => handleShowModal('handle', record)}> 查看处理意见 </a>
            </Fragment>
        ),
      },
    ];

    return (
      <GridContent>
        <React.Fragment>
          <Card
              title='合规扫描报告'
              bordered={false}
          >
            <Row>
              <Col md={8} sm={12} xs={24}>
                <a onClick={() => { this.handleFilter(reports, 'name', '主机合规扫描')}} >
                  <Statistic
                      title='主机合规报告(未读)'
                      value={numeral(13).format('0,0')}
                  />
                </a>
              </Col>
              <Col md={8} sm={12} xs={24}>
                <a onClick={() => { this.handleFilter(reports, 'name', 'docker 合规扫描')}} >
                  <Statistic
                      title='Docker容器合规报告（未读）'
                      value="9"
                  />
                </a>
              </Col>
              <Col md={8} sm={12} xs={24}>
                <a onClick={() => { this.handleFilter(reports, 'name', 'Kuberentes合规')}} >
                  <Statistic
                      title='集群合规报告（未读）'
                      value="6"
                  />
                </a>
              </Col>
            </Row>
          </Card>

          <Tabs defaultActiveKey="1">
            <TabPane tab="未读扫描报告" key="1">
              <Table
                  loading={loading}
                  dataSource={displayList}
                  columns={columns}
              />
            </TabPane>
            <TabPane tab="合规问题汇总" key="2">
              <Table
                  loading={loading}
                  dataSource={problems}
                  columns={problemColumns}
              />
            </TabPane>
          </Tabs>
        </React.Fragment>
          <Modal
            title="操作"
            visible={visible}
            width={800}
            onOk={() => handleModalOk()}
            onCancel={() => handleModalCancel()}
            okText="确认"
            cancelText="取消"
          >
          {alert}
          </Modal>
      </GridContent>
    );
  }
}

export default Reports;
