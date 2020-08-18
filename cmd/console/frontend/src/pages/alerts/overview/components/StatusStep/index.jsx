import { Alert, Steps } from 'antd';
import React, { Component } from 'react';

const { Step } = Steps;


class StatusStep extends Component {
    render() {
      const { current } = this.props;

      return (
        <Steps size="small" current={current || 0}>
            <Step title="初始" />
            <Step title="进行中" />
            <Step title="完成" />
        </Steps>
      )
    }
}

export default StatusStep;
