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
  Form,
  Popover,
  Steps,
  Select,
  Table,
  Tag,
  Row,
  Col,
  Tooltip,
  Empty,
  DatePicker,
} from 'antd';

import Link from 'umi/link';
import { GridContent, PageHeaderWrapper, RouteContext } from '@ant-design/pro-layout';
import React, { Component, Fragment } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import EventTimeline from './components/EventTimeline';
import styles from './style.less';


const ButtonGroup = Button.Group;
const { Option } = Select;
const { RangePicker } = DatePicker;
const FormItem = Form.Item;

const status = ['停止', '运行中', '已完成', '异常'];


@connect(({ container: { detail, logs, alerts, reports }, loading }) => ({
  detail,
  logs,
  detailLoad: loading.effects['container/fetchDetail'],
  logLoading: loading.effects['container/fetchLog'],
}))

class DockerContainerDetail extends Component {
    state = {
      selected: 0,
      formValues: {},
    };

    handleClick() {
      if (this.props.history) {
        this.props.history.goBack();
      }
    }

    componentDidMount() {
      const { dispatch } = this.props;
      const { formValues } = this.state;
      dispatch({
        type: 'container/fetchDetail',
        payload: this.props.match.params.container || 0,
      });
      dispatch({
        type: 'container/fetchLog',
        payload: this.props.match.params.container || 0,
      });
    }

    handleLogClick(e) {
      this.setState({
        selected: e,
      });
    }

    handleRangePickerChange(rangePickerValue) {
      const payload = {
        start: rangePickerValue[0].format('YYYY-MM-DD'),
        end: rangePickerValue[1].format('YYYY-MM-DD'),
      };
    }

    handleSearch(e) {
      e.preventDefault();
      const { dispatch, form } = this.props;
      form.validateFields((err, fieldsValue) => {
        if (err) return;
        const values = {
          ...fieldsValue,
          id: this.props.match.params.container || 0,
        };

        this.setState({
          formValues: values,
        });

        console.log(values);

        dispatch({
          type: 'container/fetchLog',
          payload: values,
        });
      });
    }

    handleFormReset = () => {
      const { form, dispatch } = this.props;
      const { formValues } = this.state;
      form.resetFields();
      this.setState({
        formValues: {},
      });

      const values = {
          id: this.props.match.params.container || 0,
      };

      dispatch({
        type: 'container/fetchLog',
        payload: {
          values,
        },
      });
    };

    render() {
      const { selected } = this.state;

      const {
        detail,
        logs,
        form: { getFieldDecorator },
      } = this.props;

      const handleClick = this.handleClick.bind(this);
      const handleItemClick = this.handleLogClick.bind(this);
      const handleRangePickerChange = this.handleRangePickerChange.bind(this);
      const handleFormReset = this.handleFormReset.bind(this);
      const handleSearch = this.handleSearch.bind(this);

      const extra = (
        <div className={styles.moreInfo}>
          <Statistic title="状态" value={status[detail.status || 0]} />
          <Statistic title="相关告警数" value={detail.total} />
        </div>
      );

      const imageId = detail.image && detail.image.key ? detail.image.key : '';
      const imageName = detail.image && detail.image.name ? detail.image.name : '';
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

      const cates = ['报警', '威胁', '日志'];
      const severity = ['严重', '中等', '信息'];
      const violations = (logs && logs.length > 0 && logs[selected] && logs[selected].details) ? (
        <div>
          {
            logs[selected].details.map((i, k) => <Link key={`lnk${i}`} to={`/detail/detailrule/${i}`}>规则{i}    </Link>)
          }
        </div>
      ) : '';

      const logDesc = (logs && logs.length > 0) ? (
        <Descriptions title="详细信息">
        <Descriptions.Item label="种类">{cates[logs[selected].category || 0]}</Descriptions.Item>
        <Descriptions.Item label="严重度">{severity[logs[selected].severity || 0]}</Descriptions.Item>
        <Descriptions.Item label="描述">{logs[selected].desc || ''}</Descriptions.Item>
        <Descriptions.Item label="时间">{logs[selected].createdAt}</Descriptions.Item>
        <Descriptions.Item label="违反的规则">{violations} </Descriptions.Item>
      </Descriptions>
      ) : (<div></div>);

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
                <Card>
                    <Row>
                      <Form onSubmit={handleSearch}>
                          <Col xl={6} lg={24} md={24} sm={24} xs={24}>
                             安全事态
                          </Col>
                          <Col xl={5} lg={24} md={24} sm={24} xs={24}>
                            <Form.Item >
                              {getFieldDecorator('category')(
                                <Select
                                  style={{ width: '100%' }}
                                  placeholder="选择事件类型">
                                  <Option value="0">动态警报</Option>
                                  <Option value="1">安全威胁</Option>
                                  <Option value="2">日志</Option>
                                </Select>,
                              )}
                            </Form.Item>
                          </Col>
                          <Col xl={5} lg={24} md={24} sm={24} xs={24}>
                            <Form.Item >
                              {getFieldDecorator('severity')(
                                <Select
                                  style={{ width: '100%' }}
                                  placeholder="选择事件类型"
                                  onChange={e => console.log(e)}>
                                  <Option value="0">严重</Option>
                                  <Option value="1">中度</Option>
                                  <Option value="2">信息</Option>
                                </Select>,
                              )}
                            </Form.Item>
                          </Col>
                          <Col xl={5} lg={24} md={24} sm={24} xs={24} >
                            <FormItem>
                              {getFieldDecorator('date')(
                                <RangePicker
                                  onChange={handleRangePickerChange}
                                />,
                              )}
                            </FormItem>
                          </Col>
                          <Col xl={3} lg={24} md={24} sm={24} xs={24}>
                            <Form.Item>
                                <Button type="primary" htmlType="submit">
                                  递交
                                </Button>
                                <Button onClick={handleFormReset}>
                                  重置
                                </Button>
                            </Form.Item>
                          </Col>
                      </Form>
                    </Row>
                </Card>
                <Card>
                  <GridContent>
                    <Row gutter={24}>
                      <Col xl={24} lg={24} md={24} sm={24} xs={24}>
                        <Card>
                          <GridContent>
                            <Row>
                              <Col xl={6} lg={24} md={24} sm={24} xs={24}>
                                <EventTimeline data={logs} handleItemClick={handleItemClick} categories={cates}/>
                              </Col>
                              <Col xl={18} lg={24} md={24} sm={24} xs={24}>
                                {logDesc}
                              </Col>
                            </Row>
                          </GridContent>
                        </Card>
                      </Col>
                    </Row>
                  </GridContent>
                </Card>
            </div>
            </PageHeaderWrapper>
        </div>
      )
    }
}

export default Form.create()(DockerContainerDetail);
