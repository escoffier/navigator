import { Result, Card, Badge, Button, Col, Row, Form, Input, Select, Modal, Table, List, message, Divider } from 'antd';
import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import { GridContent } from '@ant-design/pro-layout';
import React, { Component, Fragment } from 'react';
import { connect } from 'dva';
import styles from './BaseView.less';
import Link from 'umi/link';
import router from 'umi/router';
import k8s from '../assets/kubernetes.png';
import openshift from '../assets/openshift.png';

const statusMap = ['success', 'error'];
const status = ['运行中', '异常'];

const images = [
  <div className={styles.avatar}>
      <img src={k8s} alt="avatar" width="128" height="128"/>
  </div>,
  <div className={styles.avatar}>
      <img src={openshift} alt="avatar" width="128" height="128" />
  </div>,
];


const ClusterView = ({ record }) => (
  <Fragment>
    {record}
  </Fragment>
);

const info = (msg) => {
  message.info(msg);
};

@connect(({ settingsAndagent }) => ({
  clusters: settingsAndagent.clusters,
  deleted: settingsAndagent.clusters,
}))

class BaseView extends Component {
  state = {
    selected: 0,
    visible: false,
    content: null,
  }

  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'settingsAndagent/fetch',
    });
  }

  getRecordDisplay( record ) {
    if ( record ) {
      return (
        <Card size="small" title={`集群名称: ${record.name}`}>
          <GridContent>
            <Row gutter={24}>
              <Col xl={10} lg={24} md={24} sm={24} xs={24}>
                {record.type === 0 ? images[1]: images[0]}
                <GridContent>
                  <Row>
                    <Col xl={4}>
                      <Button type="primary" onClick={() => {}}> 修改 </Button>
                    </Col>
                  </Row>
                </GridContent>

              </Col>
              <Col xl={10} lg={24} md={24} sm={24} xs={24}>
                <List size="small"
                   header={<div> 寄生代理 | 代理类型 | 状态 </div>}
                   dataSource={record.agents}
                   renderItem={item => (
                    <List.Item>
                      <div> {`  ${item.name}  `} </div>
                      <Divider type="vertical" />
                      <div> {item.category} </div>
                      <Divider type="vertical" />
                      <Badge status={statusMap[item.status]} text={status[item.status]} />
                    </List.Item>
                   )}
                />
              </Col>
            </Row>
          </GridContent>
        </Card>
      )
    } else {
      return (
        <div className={styles.avatar_title}>
           <div>没有配置集群? <Link to="/config/cluster/add">添加集群</Link></div>
        </div>
      );
    }
  }

  handleSelectRows(e) {
    this.setState({
      selected: e,
    })
  }

  handleDisplay(event, content) {
    let displayContent = null;
    if (event == 'delete') {
      displayContent = (
        <div>
           <Result
            status="warning"
            title={`删除集群${content.name}将会导致所有运行中的代理被删除`}
          />
        </div>
      )
    }

    this.setState({
      visible: true,
      content: displayContent,
    });
  }

  handleModalOk(params) {
    const { dispatch } = this.props;
    dispatch({
      type: 'settingsAndagent/deleteCluster',
      payload: params
    });

    this.setState({
      visible: false,
      content: null,
    });

    dispatch({
      type: 'settingsAndagent/fetch',
    });
  }

  handleModalCancel() {
    this.setState({
      visible: false,
      content: null,
    });
  }

  handleNewCluster() {
    router.push({
      pathname: '/config/cluster/add',
    });
  }

  render() {
    const {
      form: { getFieldDecorator },
      clusters,
      deleted,
    } = this.props;
    const { selected, visible, content } = this.state;
    const record = clusters ? clusters[selected]: null;
    const handleSelectRows = this.handleSelectRows.bind(this);
    const handleModalOk = this.handleModalOk.bind(this);
    const handleModalCancel = this.handleModalCancel.bind(this);
    const handleDisplay = this.handleDisplay.bind(this);
    const handleNewCluster = this.handleNewCluster.bind(this);
    let i = 0;

    const displayclusters = clusters.map(function(e) {
      e.key = i;
      i += 1;
      return e;
    });

    const columns = [
      {
        title: '名称',
        dataIndex: 'name',
        key: 'name',
      },
      {
        title: '类型',
        dataindex: "type",
        render: (val) => {
          return <div>Kubernetes</div>
        }
      },
      {
        title: '代理数',
        render: (text, record) => (
          <a onClick={() => {}}>
            {record.total}
          </a>)
      },
      {
        title: '操作',
        render: (text, record) => (
          <Fragment>
            <a onClick={() => handleDisplay('delete', record)}>
              删除
            </a>
            <Divider type="vertical" />
            <a onClick={() => handleSelectRows(record.key)}>
              查看
            </a>
          </Fragment>
        ),
      },
    ];

    return (
      <div className={styles.baseView}>
        <GridContent>
          <Row>
            <Button type="primary" shape="round" onClick={() => handleNewCluster()}> 添加新集群 </Button>
          </Row>
          <Row gutter={24}>
            <Col xl={12} lg={24} md={24} sm={24} xs={24}>
              <Table
                dataSource={displayclusters}
                columns={columns}
                onSelectRow={handleSelectRows}
              />
            </Col>
            <Col xl={12} lg={24} md={24} sm={24} xs={24}>
              <ClusterView record={this.getRecordDisplay(record)}/>
            </Col>
          </Row>
        </GridContent>
        <Modal
          title="操作"
          visible={visible}
          onOk={() => handleModalOk(clusters[selected])}
          onCancel={handleModalCancel}
          width="full"
        >
          {content}
        </Modal>

      </div>
    );
  }
}

export default Form.create()(BaseView);
