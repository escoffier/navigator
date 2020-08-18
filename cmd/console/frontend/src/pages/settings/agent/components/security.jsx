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



@connect(({ settingsAndagent }) => ({
  agents: settingsAndagent.agents,
}))

class SecurityView extends Component {
  state = {
    selected: 0,
    visible: false,
    content: null,
    deleteId: null,
    newAgentVisible: false,
    path: '/config/agent/add/monitor',
  }

  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'settingsAndagent/fetchAgents',
    });
  }

  getRecordDisplay( record ) {
    if ( record ) {
      return (
        <Card size="small" title={`集群名称: ${record.name}`}>
          <GridContent>
            <Row gutter={24}>
              <Col xl={14} lg={24} md={24} sm={24} xs={24}>
                {record.category == 'Kubernetes' ? images[0]: images[1]}
                <GridContent>
                  <Row>
                    <Col xl={10}>
                      <div> Service账号: {record.serviceAccount } </div>
                      <div> 角色: {record.serviceAccount } </div>
                    </Col>
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
           <div>没有配置代理? <Link to="/config/agent/add/">添加新代理</Link></div>
        </div>
      );
    }
  }

  handleSelectRows(e) {
    this.setState({
      selected: e,
    })
  }

  handleSelectModal(e) {
    this.setState({
      path: `/config/agent/add/${e}`,
    })
  }

  handleDisplay(event, content) {
    let displayContent = null;
    if (event === 'delete') {
      this.setState({
        deleteId: content.id,
      });

      displayContent = (
        <div>
           <Result
            status="warning"
            title={`确定删除${content.id}?`}
          />
        </div>
      )
    } else if (event === 'restart') {
      displayContent = (
        <div>
           <Result
            status="warning"
            title={`确定重启${content.name}?`}
          />
        </div>
      )
    }

    this.setState({
      visible: true,
      content: displayContent,
    });
  }

  handleModalOk() {
    const { dispatch } = this.props;
    const { deleteId } = this.state;
    this.setState({
      visible: false,
      content: null,
    });

    dispatch({
      type: 'settingsAndagent/deleteAgent',
      payload: {id: deleteId},
    });
  }

  handleModalCancel() {
    this.setState({
      visible: false,
      newAgentVisible: false,
      content: null,
    });
  }

  handleNewModalOk() {
    const { path } = this.state;
    this.setState({
      newAgentVisible: false
    });

    if (path) {
      router.push({
        pathname: path,
      });
    }
  }

  handleNewAgent() {
    this.setState({
      newAgentVisible: true
    });
  }

  render() {
    const {
      agents,
    } = this.props;
    const { visible, content, newAgentVisible } = this.state;
    const handleSelectRows = this.handleSelectRows.bind(this);
    const handleModalOk = this.handleModalOk.bind(this);
    const handleModalCancel = this.handleModalCancel.bind(this);
    const handleDisplay = this.handleDisplay.bind(this);
    const handleNewAgent = this.handleNewAgent.bind(this);
    const handleNewModalOk = this.handleNewModalOk.bind(this);
    const handleSelectModal = this.handleSelectModal.bind(this);

    const columns = [
      {
        title: '名称',
        dataIndex: 'id',
        key: 'id',
      }, {
        title: '类型',
        dataIndex: 'type',
      },
      {
        title: '状态',
        render: (text, record) => {
          const index = record.running ? 1: 0;
          return (
              <Badge status={statusMap[index]} text={status[index]} />
          )
        }
      },
      {
        title: '上次更新时间',
        dataIndex: 'heartbeats',
        render: (text, record) => {
          const updated = record.heartbeats;
          return (
              <div> {updated} </div>
          )
        }
      },
      // {
      //   title: '部署方式',
      //   render: (text, record) => (
      //     <div> {`${record.parent.type}: ${record.parent.name}`}</div>
      //   ),
      // },
      {
        title: '操作',
        render: (text, record) => (
          <Fragment>
            <a onClick={() => handleDisplay('delete', record)}>
              删除
            </a>
            <Divider type="vertical" />
            {(record.status === 1)? <a onClick={() => handleDisplay('restart', record)}>
              重启
            </a>: ''}
          </Fragment>
        ),
      },
    ];

    return (
      <div className={styles.baseView}>
        <GridContent>
          <Row>
            <Button type="primary" shape="round" onClick={() => handleNewAgent()}> 添加新代理 </Button>
          </Row>
          <Row gutter={24}>
              <Table
                dataSource={agents}
                columns={columns}
                onSelectRow={handleSelectRows}
              />
          </Row>
        </GridContent>
        <Modal
          title="操作"
          visible={visible}
          onOk={handleModalOk}
          onCancel={handleModalCancel}
          width="full"
        >
          {content}
        </Modal>
        <Modal
          title="操作"
          visible={newAgentVisible}
          onOk={handleNewModalOk}
          onCancel={handleModalCancel}
        >
          <div>
            <Select style={{ width: 360 }} defaultValue="monitor" placeholder="选择代理类型" onChange={handleSelectModal}>
              <Select.Option value="monitor">集群监测代理</Select.Option>
              {/*<Select.Option value="docker">Docker节点监测</Select.Option>*/}
              {/*<Select.Option value="sidecar">集群Sidecard代理</Select.Option>*/}
              {/*<Select.Option value="image">镜像扫描器</Select.Option>*/}
              {/*<Select.Option value="compliance">合规扫描器</Select.Option>*/}
            </Select>
          </div>
        </Modal>

      </div>
    );
  }
}

export default SecurityView;
