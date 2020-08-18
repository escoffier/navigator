import { Card, Radio } from 'antd';
import { FormattedMessage } from 'umi-plugin-react/locale';
import React from 'react';
import { Pie } from './Charts';
import Yuan from '../utils/Yuan';
import styles from '../style.less';

const ProportionSales = ({
  dropdownGroup,
  salesType,
  loading,
  salesPieData,
  handleChangeSalesType,
}) => (
  <Card
    loading={loading}
    className={styles.salesCard}
    bordered={false}
    title={
      <FormattedMessage
        id="dashboardandanalysis.analysis.alert-distribution"
        defaultMessage="The Alerts Distribution"
      />
    }
    style={{
      height: '100%',
    }}
    extra={
      <div className={styles.salesCardExtra}>
        {dropdownGroup}
        <div className={styles.salesTypeRadio}>
          <Radio.Group value={salesType} onChange={handleChangeSalesType}>
            <Radio.Button value="host">
              <FormattedMessage id="dashboardandanalysis.channel.host" defaultMessage="ALL" />
            </Radio.Button>
            <Radio.Button value="container">
              <FormattedMessage id="dashboardandanalysis.channel.containers" defaultMessage="Online" />
            </Radio.Button>
            <Radio.Button value="cluster">
              <FormattedMessage id="dashboardandanalysis.channel.microservices" defaultMessage="Stores" />
            </Radio.Button>
          </Radio.Group>
        </div>
      </div>
    }
  >
    <div>
      <h4
        style={{
          marginTop: 8,
          marginBottom: 32,
        }}
      >
        <FormattedMessage id="dashboardandanalysis.analysis.total-alerts" defaultMessage="Alerts" />
      </h4>
      <Pie
        hasLegend
        subTitle={
          <FormattedMessage id="dashboardandanalysis.analysis.total-alerts" defaultMessage="Alerts" />
        }
        total={() => <div>{salesPieData.reduce((pre, now) => now.y + pre, 0)}</div>}
        data={salesPieData}
        valueFormat={value => {value}}
        height={248}
        lineWidth={4}
      />
    </div>
  </Card>
);

export default ProportionSales;
