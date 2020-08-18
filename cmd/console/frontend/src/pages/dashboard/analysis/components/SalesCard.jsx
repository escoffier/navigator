import { Card, Col, DatePicker, Row, Tabs } from 'antd';
import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import React from 'react';
import numeral from 'numeral';
import { Bar } from './Charts';
import styles from '../style.less';

const { RangePicker } = DatePicker;
const { TabPane } = Tabs;


const SalesCard = ({
  rangePickerValue,
  salesData,
  isActive,
  handleRangePickerChange,
  handleChangeData,
  loading,
  selectDate, rankingListData,
}) => (
  <Card
    loading={loading}
    bordered={false}
    bodyStyle={{
      padding: 0,
    }}
  >
    <div className={styles.salesCard}>
      <Tabs
        tabBarExtraContent={
          <div className={styles.salesExtraWrap}>
            <div className={styles.salesExtra}>
              <a className={isActive('today')} onClick={() => selectDate('today')}>
                <FormattedMessage
                  id="dashboardandanalysis.analysis.all-day"
                  defaultMessage="All Day"
                />
              </a>
              <a className={isActive('week')} onClick={() => selectDate('week')}>
                <FormattedMessage
                  id="dashboardandanalysis.analysis.all-week"
                  defaultMessage="All Week"
                />
              </a>
              <a className={isActive('month')} onClick={() => selectDate('month')}>
                <FormattedMessage
                  id="dashboardandanalysis.analysis.all-month"
                  defaultMessage="All Month"
                />
              </a>
              <a className={isActive('year')} onClick={() => selectDate('year')}>
                <FormattedMessage
                  id="dashboardandanalysis.analysis.all-year"
                  defaultMessage="All Year"
                />
              </a>
            </div>
            <RangePicker
              value={rangePickerValue}
              onChange={handleRangePickerChange}
              style={{
                width: 256,
              }}
            />
          </div>
        }
        size="large"
        tabBarStyle={{
          marginBottom: 24,
        }}
        onTabClick = {handleChangeData}
      >
        <TabPane
          tab={<FormattedMessage id="dashboardandanalysis.analysis.total-alerts" defaultMessage="Alerts" />}
          key="all"
        >
          <Row type="flex">
            <Col xl={16} lg={12} md={12} sm={24} xs={24}>
              <div className={styles.salesBar}>
                <Bar
                  height={295}
                  title={
                    <FormattedMessage
                      id="dashboardandanalysis.analysis.alerts-trend"
                      defaultMessage="Sales Trend"
                    />
                  }
                  data={salesData}
                />
              </div>
            </Col>
            <Col xl={8} lg={12} md={12} sm={24} xs={24}>
              <div className={styles.salesRank}>
                <h4 className={styles.rankingTitle}>
                  <FormattedMessage
                    id="dashboardandanalysis.analysis.alerts-assets-ranking"
                    defaultMessage="Sales Ranking"
                  />
                </h4>
                <ul className={styles.rankingList}>
                  {rankingListData.map((item, i) => (
                    <li key={item.title}>
                      <span className={`${styles.rankingItemNumber} ${i < 3 ? styles.active : ''}`}>
                        {i + 1}
                      </span>
                      <span className={styles.rankingItemTitle} title={item.title}>
                        {item.title}
                      </span>
                      <span className={styles.rankingItemValue}>
                        {numeral(item.value).format('0,0')}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </Col>
          </Row>
        </TabPane>
        <TabPane
          tab={
            <FormattedMessage id="dashboardandanalysis.analysis.total-vulnerabilities" defaultMessage="Vulnerabilities" />
          }
          key="critical"
        >
          <Row>
            <Col xl={16} lg={12} md={12} sm={24} xs={24}>
              <div className={styles.salesBar}>
                <Bar
                  height={292}
                  title={
                    <FormattedMessage
                      id="dashboardandanalysis.analysis.vulnerabilities-trend"
                      defaultMessage="Visits Trend"
                    />
                  }
                  data={salesData}
                />
              </div>
            </Col>
            <Col xl={8} lg={12} md={12} sm={24} xs={24}>
              <div className={styles.salesRank}>
                <h4 className={styles.rankingTitle}>
                  <FormattedMessage
                    id="dashboardandanalysis.analysis.threat-assets-ranking"
                    defaultMessage="Visits Ranking"
                  />
                </h4>
                <ul className={styles.rankingList}>
                  {rankingListData.map((item, i) => (
                    <li key={item.title}>
                      <span className={`${styles.rankingItemNumber} ${i < 3 ? styles.active : ''}`}>
                        {i + 1}
                      </span>
                      <span className={styles.rankingItemTitle} title={item.title}>
                        {item.title}
                      </span>
                      <span>{numeral(item.total).format('0,0')}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Col>
          </Row>
        </TabPane>
      </Tabs>
    </div>
  </Card>
);

export default SalesCard;
