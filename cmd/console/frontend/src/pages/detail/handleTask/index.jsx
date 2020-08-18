import {
  Badge,
  Button,
  Card,
  Statistic,
  Descriptions,
  Divider,
  Dropdown,
  DatePicker,
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
} from 'antd';

import Link from 'umi/link';

import { GridContent, PageHeaderWrapper, RouteContext } from '@ant-design/pro-layout';
import React, { Component, Fragment } from 'react';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import styles from './style.less';


const ButtonGroup = Button.Group;
const { Option } = Select;
const { RangePicker } = DatePicker;
const FormItem = Form.Item;


@connect(({ handleTask, loading }) => ({
  handleTask,
  loading: loading.effects['handleTask/fetch'],
}))
class HandleTaskDetail extends Component {
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
        payload: {
          id: this.props.match.params.container || 0,
        },
      });
      dispatch({
        type: 'container/fetchLog',
        payload: {
          ...formValues,
          id: this.props.match.params.container || 0,
        },
      });
    }

    handleAlertClick(e) {
      console.log(e);
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

      const handleClick = this.handleClick.bind(this);
      const handleAlertClick = this.handleAlertClick.bind(this);
      const handleRangePickerChange = this.handleRangePickerChange.bind(this);
      const handleFormReset = this.handleFormReset.bind(this);
      const handleSearch = this.handleSearch.bind(this);
      const { query } = this.props.location;
      const alerts = query.alerts || [];
      const tags = (<span>
        {alerts.map(tag => {
          let color = tag.length > 5 ? 'geekblue' : 'green';
          return (
            <Tag color={color} key={tag.key}>
              <a onClick={()=> handleAlertClick(tag)}>{tag.key.toUpperCase()}</a>
            </Tag>
          );
        })}
      </span>)

      const taskId = (this.props.match.params.task === 'new') ? undefined: this.props.match.params.task;


      const description = (
            <Descriptions className={styles.headerList} size="small" column={2}>
              <Descriptions.Item label="创建人">管理员</Descriptions.Item>
              <Descriptions.Item label="相关报警">{tags}</Descriptions.Item>
              <Descriptions.Item label="处理单号">{taskId}</Descriptions.Item>
              <Descriptions.Item label="指派人"></Descriptions.Item>
            </Descriptions>
      );

      const action = (
          <Fragment>
            <Button type="primary" onClick={handleClick}>
              <Icon type="left" />
               <FormattedMessage id="container.operation.goback" />
            </Button>
            <ButtonGroup>
              <Button>保存</Button>
              <Button>标记完成</Button>
              <Button>删除</Button>
            </ButtonGroup>
          </Fragment>
      );

      return (
        <div>
            <PageHeaderWrapper
              title={'处理告警'}
              extra={action}
              className={styles.pageHeader}
              content={description}
            >
            <div className={styles.main}>
            </div>
            </PageHeaderWrapper>
        </div>
      )
    }
}

export default Form.create()(HandleTaskDetail);
