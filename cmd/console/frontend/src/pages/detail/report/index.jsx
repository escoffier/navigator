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


@connect(({ reportAndDetail, loading }) => ({
  reportAndDetail,
  loading: loading.effects['reportAndDetail/fetch'],
}))
class ReportDetail extends Component {
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
      console.log(this.props.match.params.report);

      dispatch({
        type: 'reportAndDetail/fetch',
        payload: {
          id: this.props.match.params.report || 0,
        },
      });
    }

    handleAlertClick(e) {
      console.log(e);
      this.setState({
        selected: e,
      });
    }

    render() {
      const { reportAndDetail: { detail } } = this.props;

      const handleClick = this.handleClick.bind(this);
      const { query } = this.props.location;

      const description = (
            <Descriptions className={styles.headerList} size="small" column={2}>
              <Descriptions.Item label="扫描类型">{detail.name || ""}</Descriptions.Item>
              <Descriptions.Item label="扫描时间">{detail.finished || ""}</Descriptions.Item>
              <Descriptions.Item label="问题数">{detail.total || ""}</Descriptions.Item>
              <Descriptions.Item label="严重问题数">{detail.critical || ""}</Descriptions.Item>
            </Descriptions>
      );

      const action = (
          <Fragment>
            <Button type="primary" onClick={handleClick}>
              <Icon type="left" />
               <FormattedMessage id="container.operation.goback" />
            </Button>
            <ButtonGroup>
              <Button>导出</Button>
              <Button>标记已读</Button>
            </ButtonGroup>
          </Fragment>
      );

      return (
        <div>
            <PageHeaderWrapper
              title={'查看报告细节'}
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

export default Form.create()(ReportDetail);
