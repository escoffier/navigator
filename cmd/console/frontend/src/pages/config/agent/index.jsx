// import { Card, Col, Form, List, Row, Select, Typography } from 'antd';
import {
  Form,
  Select,
  Result,
  InputNumber,
  Switch,
  Steps,
  Radio,
  Slider,
  Button,
  List,
  Card,
  Upload,
  Icon,
  Rate,
  Checkbox,
  Row,
  Col,
  Tag,
  Input,
  Modal,
  message,
} from 'antd';

import React, { Component } from 'react';
import { GridContent } from '@ant-design/pro-layout';
import Link from 'umi/link';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';

const { Step } = Steps;
const formItemLayout = {
  labelCol: { span: 6 },
  wrapperCol: { span: 14 },
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

let timer = null;

const progressDescription = [
  '初始化.... ..........',
  '开启服务端口..........',
  '开启服务.... ........',
  '等待代理端连接........',
  '等待代理端连接........',
  '等待代理端连接........',
  '获取代理端信息........',
  '下载信息到代理端.......',
  '注册代理端............',
  '更新数据库............',
  '完成配置..............',
];

const marks = {
  0: '0',
  37: '0.37',
  50: '0.5',
  100: {
    style: {
      color: '#f50',
    },
    label: <strong>1</strong>,
  },
};

const markMemory = {
  0: '100M',
  37: '500M',
  50: '1G',
  100: {
    style: {
      color: '#f50',
    },
    label: <strong>2G</strong>,
  },
};

@connect(({ configAgentCreate }) => ({
  configAgentCreate,
}))

class AgentCreate extends Component {
    state = {
      current: 0,
      visible: false,
      category: 'monitor',
      config: {},
      commandType: 'yaml',
      progress: 0,
    };

    progress() {
      const value = this.state.progress + 1;
      this.setState({
        progress: value,
      });

      if (value >= 10) {
        this.setState({
          progress: 10,
        });

        clearInterval(timer);
      }
    }

    handleRun() {
      this.setState({
        progress: 0,
      });
      timer = setInterval(this.progress.bind(this), 500);
    }

    componentDidMount() {
      this.setState({
        category: this.props.match.params || 'monitor',
      })
    }

    handleClick() {
      message.success('添加完成');
      sleep(2000);
      if (this.props.history) {
       this.props.history.goBack();
      }
    }

    renderMonitor() {
      const {
        form: { getFieldDecorator },
      } = this.props;
      const handleSubmit = this.handleSubmit.bind(this);
      return (
          <Card title="填写集群监控代理基本信息">
            <Form {...formItemLayout} onSubmit={handleSubmit}>
              <Form.Item label="代理名称">
                {getFieldDecorator('ruleName', {
                  rules: [
                    {
                      required: true,
                      message: '请输入代理名!',
                    },
                  ],
                })(<Input />)}
              </Form.Item>
              <Form.Item label="本机地址">
                {getFieldDecorator('ip', {
                  rules: [
                    {
                      required: true,
                      message: '请输入本服务IP!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
              <Form.Item label="允许Privileged">
                {getFieldDecorator('privilege')(<Switch defaultChecked />)
                }
              </Form.Item>
              <Form.Item label="允许监测Host网络">
                {getFieldDecorator('network')(<Switch defaultChecked />)
                }
              </Form.Item>
              <Form.Item label="选择寄生集群" hasFeedback>
              {getFieldDecorator('node', {
                rules: [{ required: true, message: '请选择集群!' }],
              })(
                <Select>
                  <Select.Option value="0">集群1</Select.Option>
                  {/*<Select.Option value="1">集群2</Select.Option>*/}
                  {/*<Select.Option value="2">集群3</Select.Option>*/}
                </Select>,
              )}
            </Form.Item>
            <Form.Item label="选择命名空间" hasFeedback>
              {getFieldDecorator('namespace', {
                rules: [{ required: true, message: '选择命名空间!' }],
              })(
                <Select>
                  <Select.Option value="default">default</Select.Option>
                  <Select.Option value="vegeta">vegeta</Select.Option>
                </Select>,
              )}
            </Form.Item>
            <Form.Item label="选择CPU资源限制 " hasFeedback>
              {getFieldDecorator('cpu', {initialValue: 37})(
                <Slider marks={marks} step={null}  />
              )}
            </Form.Item>
             <Form.Item label="选择Memory资源限制 " hasFeedback>
              {getFieldDecorator('memory', {initialValue: 37})(
                <Slider marks={markMemory} step={null} />
              )}
            </Form.Item>
            </Form>
          </Card>
      );
    }

    renderImage() {
      const {
        form: { getFieldDecorator },
      } = this.props;
      const handleSubmit = this.handleSubmit.bind(this);
      return (
          <Card title="填写镜像扫描代理基本信息">
            <Form {...formItemLayout} onSubmit={handleSubmit}>
              <Form.Item label="代理名称">
                {getFieldDecorator('ruleName', {
                  rules: [
                    {
                      required: true,
                      message: '请输入规则名!',
                    },
                  ],
                })(<Input />)}
              </Form.Item>
              <Form.Item label="本机地址">
                {getFieldDecorator('ip', {
                  rules: [
                    {
                      required: true,
                      message: '请输入本机地址!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
              <Form.Item label="填写情报Token">
                {getFieldDecorator('token', {
                  rules: [
                    {
                      required: true,
                      message: '请输入情报Token!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
              <Form.Item label="选择CPU资源限制 " hasFeedback>
              {getFieldDecorator('cpu', {initialValue: 37})(
                <Slider marks={marks} step={null} />
              )}
            </Form.Item>
              <Form.Item label="选择Memory资源限制 " hasFeedback>
              {getFieldDecorator('memory', {initialValue: 37})(
                <Slider marks={markMemory} step={null} />
              )}
            </Form.Item>
            <Form.Item label="输入镜像仓库地址" hasFeedback>
              {getFieldDecorator('registry', {
              })(
                <Input />
              )}
            </Form.Item>
            <Form.Item label="用户名 " hasFeedback>
              {getFieldDecorator('username', {
              })(
                <Input />
              )}
            </Form.Item>
            <Form.Item label="密码 " hasFeedback>
              {getFieldDecorator('password', {
              })(
                <Input.Password />
              )}
            </Form.Item>
            </Form>
          </Card>
      );
    }

    renderCompliance() {
      const {
        form: { getFieldDecorator },
      } = this.props;
      const handleSubmit = this.handleSubmit.bind(this);
      return (
          <Card title="填写Compliance代理基本信息">
            <Form {...formItemLayout} onSubmit={handleSubmit}>
              <Form.Item label="代理名称">
                {getFieldDecorator('ruleName', {
                  rules: [
                    {
                      required: true,
                      message: '请输入规则名!',
                    },
                  ],
                })(<Input />)}
              </Form.Item>
              <Form.Item label="本机地址">
                {getFieldDecorator('ip', {
                  rules: [
                    {
                      required: true,
                      message: '请输入本机地址!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
              <Form.Item label="填写情报Token">
                {getFieldDecorator('token', {
                  rules: [
                    {
                      required: true,
                      message: '请输入情报Token!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
            </Form>
          </Card>
      );
    }

    renderSidercar() {
      const {
        form: { getFieldDecorator },
      } = this.props;
      const handleSubmit = this.handleSubmit.bind(this);
      return (
          <Card title="填写Sidecar代理基本信息">
            <Form {...formItemLayout} onSubmit={handleSubmit}>
              <Form.Item label="代理名称">
                {getFieldDecorator('ruleName', {
                  rules: [
                    {
                      required: true,
                      message: '请输入规则名!',
                    },
                  ],
                })(<Input />)}
              </Form.Item>
              <Form.Item label="本机地址">
                {getFieldDecorator('ip', {
                  rules: [
                    {
                      required: true,
                      message: '请输入本机地址!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
              <Form.Item label="允许Privileged" checked>
                {getFieldDecorator('privilege')(<Switch defaultChecked />)
                }
              </Form.Item>
              <Form.Item label="允许监测Host网络" checked>
                {getFieldDecorator('network')(<Switch defaultChecked />)
                }
              </Form.Item>
              <Form.Item label="选择寄生集群" hasFeedback>
              {getFieldDecorator('node', {
                rules: [{ required: true, message: '请选择集群!' }],
              })(
                <Select>
                  <Select.Option value="0">集群1</Select.Option>
                  <Select.Option value="1">集群2</Select.Option>
                  <Select.Option value="2">集群3</Select.Option>
                </Select>,
              )}
            </Form.Item>
            <Form.Item label="选择命名空间" hasFeedback>
              {getFieldDecorator('namespace', {
                rules: [{ required: true, message: '选择命名空间!' }],
              })(
                <Select>
                  <Select.Option value="0">default</Select.Option>
                  <Select.Option value="1">production</Select.Option>
                  <Select.Option value="2">developer</Select.Option>
                </Select>,
              )}
            </Form.Item>
            <Form.Item label="选择CPU资源限制 " hasFeedback>
              {getFieldDecorator('cpu', {
              })(
                <Slider marks={marks} step={null} defaultValue={37} />
              )}
            </Form.Item>
             <Form.Item label="选择Memory资源限制 " hasFeedback>
              {getFieldDecorator('memory', {
              })(
                <Slider marks={markMemory} step={null} defaultValue={37} />
              )}
            </Form.Item>
            </Form>
          </Card>
      );
    }

    renderDocker() {
      const {
        form: { getFieldDecorator },
      } = this.props;

      const handleSubmit = this.handleSubmit.bind(this);

      return (
          <Card title="填写Docker代理基本信息">
            <Form {...formItemLayout} onSubmit={handleSubmit}>
              <Form.Item label="代理名称">
                {getFieldDecorator('ruleName', {
                  rules: [
                    {
                      required: true,
                      message: '请输入规则名!',
                    },
                  ],
                })(<Input />)}
              </Form.Item>
              <Form.Item label="本机地址">
                {getFieldDecorator('ip', {
                  rules: [
                    {
                      required: true,
                      message: '请输入本机地址!',
                    },
                  ],
                })(<Input placeholder="localhost"/>)}
              </Form.Item>
              <Form.Item label="Docker位置">
                {getFieldDecorator('docker', {
                  rules: [
                    {
                      required: true,
                      message: '请输入Docker的位置',
                    },
                  ],
                })(<Input placeholder="/var/run/docker.sock"/>)}
              </Form.Item>
              <Form.Item label="允许Privileged">
                {getFieldDecorator('privilege')(<Switch defaultChecked />)
                }
              </Form.Item>
              <Form.Item label="允许监测Host网络">
                {getFieldDecorator('network')(<Switch defaultChecked />)
                }
              </Form.Item>
            <Form.Item label="选择CPU资源限制 " hasFeedback>
              {getFieldDecorator('cpu', {
              })(
                <Slider marks={marks} step={null} defaultValue={37} />
              )}
            </Form.Item>
             <Form.Item label="选择Memory资源限制 " hasFeedback>
              {getFieldDecorator('memory', {
              })(
                <Slider marks={markMemory} step={null} defaultValue={37} />
              )}
            </Form.Item>
            </Form>
          </Card>
      );
    }

    handleSubmit() {
        const { dispatch } = this.props;
        this.props.form.validateFields((err, values) => {
            if (!err) {
                console.log('Submit create agent', values);
            }

            dispatch({
                type: 'configAgentCreate/create',
                payload: values,
            });
        });
    }

    handleCommandOption(e) {
      this.setState({
        commandType: e,
      })
    }

    next() {
      const { current } = this.state;
      const { dispatch } = this.props;
      const {
        form: { validateFields },
      } = this.props;

      if (current === 0) {
        validateFields((errors, values) => {
          if (errors) {
            return;
          }


        this.setState({
            config: values,
            current: current + 1,
          })
        });
      } else if (current === 1) {
        const { config } = this.state;
        console.log(config);
        dispatch({
          type: 'configAgentCreate/create',
          payload: config,
        });

        this.handleRun();
        const current = this.state.current + 1;
        this.setState({ current });
      } else {
        const current = this.state.current + 1;
        this.setState({ current });
      }
    }

    back() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    prev() {
      const current = this.state.current - 1;
      this.setState({ current });
    }

    render() {
      const { category } = this.props.match.params || 'monitor';
      const handleClick = this.handleClick.bind(this);
      const handleSubmit = this.handleSubmit.bind(this);
      const handleCommandOption = this.handleCommandOption.bind(this);
      const { current, commandType, config, progress} = this.state;
      const back = this.back.bind(this);

      const renderFunction = () => {
        if (category === 'monitor') {
          return this.renderMonitor.bind(this);
        } if (category === 'docker') {
          return this.renderDocker.bind(this);
        } if (category === 'image') {
          return this.renderImage.bind(this);
        } if (category === 'compliance') {
          return this.renderCompliance.bind(this);
        } if (category === 'sidecar') {
          return this.renderSidercar.bind(this);
        }
      };

      const commandToRun = {
          helm: (
              <p>
                <code>
                  {`helm get arksec.io/redstone-${category} && helm install --hostIp ${config.ip} --name ${config.ruleName} redstone-${category}`}
                </code>
              </p>
          ),
          yaml: (
              <p>
                <code>
                   {`curl -O https://arksec.io/download/config/redstone-${category}.yaml && kubectl apply --hostIp ${config.ip} --name ${config.ruleName} redstone-${category}.yaml`}
                </code>
              </p>
          ),
          docker: (
             <p>
                <code>
                  {`docker run --privileged --name ${config.ruleName} arksec.io/redstone-${category}:latest`}
                </code>
             </p>
          ),
          default: (
            <div>无法用该方法部署，请选择别的部署方式</div>
          ),
        };

      const commandContent = (category === 'docker') ? (
        <div>
        <Card title="1. 选择部署方式">
          <Select style={{ width: 360 }} placeholder="选择部署方式" onChange={handleCommandOption}>
            <Option value="docker">用Docker命令安装</Option>
          </Select>
        </Card>
        <Card title="2. 请运行以下命令">
          {commandToRun['docker']}
        </Card>
        </div>
      ):(
        <div>
        <Card title="1. 选择部署方式">
          <Select style={{ width: 360 }} placeholder="选择部署方式" onChange={handleCommandOption}>
            <Option value="helm">用Helm Chart安装</Option>
            <Option value="yaml">用Yaml安装</Option>
            <Option value="docker">用Docker命令安装</Option>
          </Select>
        </Card>
        <Card title="2. 请运行以下命令">
          {commandToRun[commandType]}
        </Card>
        </div>
      );

      const steps = [
        {
          title: '第一步',
          content: renderFunction()(),
        },
        {
          title: '第二步',
          content: commandContent,
        },
        {
          title: '第三步',
          content: (<Card title="部署进度">
                    <List
                      bordered
                      dataSource={progressDescription.slice(0, progress)}
                      renderItem={item => <List.Item>{item} <Icon type="check" /></List.Item>}
                    />
                   </Card>),
        },
      ];

      return (
        <div>
          <Steps current={current}>
            {steps.map(item => (
              <Step key={item.title} title={item.title} />
            ))}
          </Steps>
          <div className="steps-content">
            {steps[current].content}
          </div>
          <div className="steps-action">
            {current < steps.length - 1 && (
              <Button onClick={() => this.next()}>
                下一步
              </Button>
            )}
            {current == 0 && (
              <Button onClick={() => back()}>
                取消
              </Button>
            )}
            {current === steps.length - 1 && (
              <Button type='primary' disabled={!(progress === 10)} onClick={handleClick}>
                完成
              </Button>
            )}
            {current == 1 && (
              <Button style={{ marginLeft: 8 }} onClick={() => this.prev()}>
                上一步
              </Button>
            )}
          </div>
        </div>
      );

      // return (
      //
      //   {/*<div>{renderFunction()()}</div>*/}
      // );
    }
}

export default Form.create()(AgentCreate);
