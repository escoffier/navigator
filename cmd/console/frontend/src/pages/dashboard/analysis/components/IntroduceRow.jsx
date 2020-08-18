import { Col, Icon, Row, Tooltip } from 'antd';
import { FormattedMessage } from 'umi-plugin-react/locale';
import React from 'react';
import numeral from 'numeral';
import { ChartCard, MiniArea, MiniBar, MiniProgress, Field } from './Charts';
import Trend from './Trend';
import Yuan from '../utils/Yuan';
import styles from '../style.less';
import Link from 'umi/link';

const topColResponsiveProps = {
  xs: 24,
  sm: 12,
  md: 12,
  lg: 12,
  xl: 6,
  style: {
    marginBottom: 24,
  },
};

const IntroduceRow = ({ loading, severityVulnerabilityData, severityAlertData, severityCheckData}) => (
  <Row gutter={24} type="flex">
    <Col {...topColResponsiveProps}>
      <ChartCard
        bordered={false}
        title={
          <FormattedMessage
            id="dashboardandanalysis.analysis.total-alerts"
            defaultMessage="Total Sales"
          />
        }
        action={
          <Link to="/alerts/overview">
          <Tooltip
            title={
              <FormattedMessage
                id="dashboardandanalysis.analysis.introduce"
                defaultMessage="Introduce"
              />
            }
          >
            <Icon type="eye" />
          </Tooltip>
          </Link>
        }
        loading={loading}
        total={() => "160"}
        footer={
          <div
            style={{
              whiteSpace: 'nowrap',
              overflow: 'hidden',
            }}
          >
            <Trend
              flag="up"
              style={{
                marginRight: 16,
              }}
            >
              <FormattedMessage
                id="dashboardandanalysis.analysis.day"
                defaultMessage="Weekly Changes"
              />
              <span className={styles.trendText}>12%</span>
            </Trend>
          </div>
        }
        contentHeight={46}
      >
      <MiniBar data={severityAlertData} />
      </ChartCard>
    </Col>
    <Col {...topColResponsiveProps}>
      <ChartCard
        bordered={false}
        title={
          <FormattedMessage
            id="dashboardandanalysis.analysis.total-vulnerabilities"
            defaultMessage="Total Sales"
          />
        }
        action={

          <Tooltip
            title={
              <FormattedMessage
                id="dashboardandanalysis.analysis.introduce"
                defaultMessage="Introduce"
              />
            }
          >
            <Link to="/alerts/vulnerabilities">
            <Icon type="eye" />
            </Link>
          </Tooltip>
        }
        loading={loading}
        total={() => "78"}
        footer={
          <div
            style={{
              whiteSpace: 'nowrap',
              overflow: 'hidden',
            }}
          >
            <Trend
              flag="down"
              style={{
                marginRight: 16,
              }}
            >
              <FormattedMessage
                id="dashboardandanalysis.analysis.day"
                defaultMessage="Weekly Changes"
              />
              <span className={styles.trendText}>6%</span>
            </Trend>
          </div>
        }
        contentHeight={46}
      >
      <MiniBar data={severityVulnerabilityData} />
      </ChartCard>
    </Col>

    <Col {...topColResponsiveProps}>
      <ChartCard
        bordered={false}
        loading={loading}
        title={
          <FormattedMessage id="dashboardandanalysis.analysis.total-compliance-checks" defaultMessage="Payments" />
        }
        action={
          <Tooltip
            title={
              <FormattedMessage
                id="dashboardandanalysis.analysis.introduce"
                defaultMessage="Introduce"
              />
            }
          >
            <Icon type="eye" />
          </Tooltip>
        }
        total={numeral(15).format('0,0')}
        footer={
          <Field
            label={
              <FormattedMessage
                id="dashboardandanalysis.analysis.compliance-passrate"
                defaultMessage="Conversion Rate"
              />
            }
            value="60%"
          />
        }
        contentHeight={46}
      >
        <MiniBar data={severityCheckData} />
      </ChartCard>
    </Col>
    <Col {...topColResponsiveProps}>
      <ChartCard
        loading={loading}
        bordered={false}
        title={
          <FormattedMessage
            id="dashboardandanalysis.analysis.risk-score"
            defaultMessage="Operational Effect"
          />
        }
        action={
          <Tooltip
            title={
              <FormattedMessage
                id="dashboardandanalysis.analysis.introduce"
                defaultMessage="Introduce"
              />
            }
          >
            <Link to="/alerts/overview">
            <Icon type="eye" />
            </Link>
          </Tooltip>
        }
        total="78%"
        footer={
          <div
            style={{
              whiteSpace: 'nowrap',
              overflow: 'hidden',
            }}
          >
            <Trend
              flag="up"
              style={{
                marginRight: 16,
              }}
            >
              <FormattedMessage
                id="dashboardandanalysis.analysis.week"
                defaultMessage="Weekly Changes"
              />
              <span className={styles.trendText}>12%</span>
            </Trend>
            <Trend flag="down">
              <FormattedMessage
                id="dashboardandanalysis.analysis.day"
                defaultMessage="Weekly Changes"
              />
              <span className={styles.trendText}>11%</span>
            </Trend>
          </div>
        }
        contentHeight={46}
      >
        <MiniProgress percent={78} strokeWidth={8} target={80} color="#13C2C2" />
      </ChartCard>
    </Col>
  </Row>
);

export default IntroduceRow;
