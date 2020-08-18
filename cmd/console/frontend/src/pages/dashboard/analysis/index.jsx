import { Col, Dropdown, Icon, Menu, Row } from 'antd';
import React, { Component, Suspense } from 'react';
import { GridContent } from '@ant-design/pro-layout';
import { connect } from 'dva';
import PageLoading from './components/PageLoading';
import { getTimeDistance } from './utils/utils';
import styles from './style.less';

const IntroduceRow = React.lazy(() => import('./components/IntroduceRow'));
const SalesCard = React.lazy(() => import('./components/SalesCard'));
const TopSearch = React.lazy(() => import('./components/TopSearch'));
const ProportionSales = React.lazy(() => import('./components/ProportionSales'));
const OfflineData = React.lazy(() => import('./components/OfflineData'));

@connect(({ dashboardAndanalysis, loading }) => ({
  dashboardAndanalysis,
  loading: loading.effects['dashboardAndanalysis/fetch'],
}))
class Analysis extends Component {
  state = {
    alertsDist: 'host',
    currentTabKey: '',
    rangePickerValue: getTimeDistance('year'),
    dataType: 'all',
  };

  reqRef = 0;

  timeoutId = 0;

  componentDidMount() {
    const { dispatch } = this.props;
    this.reqRef = requestAnimationFrame(() => {
      dispatch({
        type: 'dashboardAndanalysis/fetch',
      });
    });
  }

  componentWillUnmount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'dashboardAndanalysis/clear',
    });
    cancelAnimationFrame(this.reqRef);
    clearTimeout(this.timeoutId);
  }

  handleChangeSalesType = e => {
    this.setState({
      alertsDist: e.target.value,
    });
  };

  handleTabChange = key => {
    this.setState({
      currentTabKey: key,
    });
  };

  handleRangePickerChange = rangePickerValue => {
    const { dispatch } = this.props;
    this.setState({
      rangePickerValue,
    });
    dispatch({
      type: 'dashboardAndanalysis/fetchSalesData',
      payload: {
        start: this.state.rangePickerValue[0].format("YYYY-MM-DD"),
        end: this.state.rangePickerValue[1].format("YYYY-MM-DD"),
      },
    });
  };

  handleChangeData = (key, event) => {
    this.setState({
      dataType: key,
    });
  };

  selectDate = type => {
    const { dispatch } = this.props;
    this.setState({
      rangePickerValue: getTimeDistance(type),
    });
    dispatch({
      type: 'dashboardAndanalysis/fetchSalesData',
      payload: {
        start: this.state.rangePickerValue[0].format("YYYY-MM-DD"),
        end: this.state.rangePickerValue[1].format("YYYY-MM-DD"),
      },
    });
  };

  isActive = type => {
    const { rangePickerValue } = this.state;
    const value = getTimeDistance(type);

    if (!rangePickerValue[0] || !rangePickerValue[1]) {
      return '';
    }

    if (
      rangePickerValue[0].isSame(value[0], 'day') &&
      rangePickerValue[1].isSame(value[1], 'day')
    ) {
      return styles.currentDate;
    }

    return '';
  };

  render() {
    const { rangePickerValue, alertsDist, currentTabKey } = this.state;
    const { dashboardAndanalysis, loading } = this.props;

    const {
      visitData,
      allTimeData,
      vulnerabilityData,
      complianceData,
      complianceChartData,
      alertsDistDataHost,
      alertsDistDataContainer,
      alertsDistDataCluster,
      severityVulnerabilityData,
      severityAlertData,
      severityCheckData,
      rankingListData,
    } = dashboardAndanalysis;
    let salesPieData;

    if (alertsDist === 'host') {
      salesPieData = alertsDistDataHost;
    } else {
      salesPieData = alertsDist === 'container' ? alertsDistDataContainer : alertsDistDataCluster;
    }

    // const menu = (
    //   <Menu>
    //     <Menu.Item>操作一</Menu.Item>
    //     <Menu.Item>操作二</Menu.Item>
    //   </Menu>
    // );
    //
    // const dropdownGroup = (
    //   <span className={styles.iconGroup}>
    //     <Dropdown overlay={menu} placement="bottomRight">
    //       <Icon type="ellipsis" />
    //     </Dropdown>
    //   </span>
    // );


    const activeKey = currentTabKey || (complianceData[0] && complianceData[0].name);
    return (
      <GridContent>
        <React.Fragment>
          <Suspense fallback={<PageLoading />}>
            <IntroduceRow loading={loading} severityVulnerabilityData={severityVulnerabilityData}
                          severityAlertData={severityAlertData} severityCheckData={severityCheckData}/>
          </Suspense>
          <Suspense fallback={null}>
            <SalesCard
              rangePickerValue={rangePickerValue}
              salesData={allTimeData? allTimeData[this.state.dataType]: []}
              isActive={this.isActive}
              handleRangePickerChange={this.handleRangePickerChange}
              handleChangeData={this.handleChangeData}
              loading={loading}
              selectDate={this.selectDate}
              rankingListData={rankingListData}
            />
          </Suspense>
          <Row
            gutter={24}
            type="flex"
            style={{
              marginTop: 24,
            }}
          >
            <Col xl={12} lg={24} md={24} sm={24} xs={24}>
              <Suspense fallback={null}>
                <ProportionSales
                  // dropdownGroup={dropdownGroup}
                  salesType={alertsDist}
                  loading={loading}
                  salesPieData={salesPieData}
                  handleChangeSalesType={this.handleChangeSalesType}
                />
              </Suspense>
            </Col>
            <Col xl={12} lg={24} md={24} sm={24} xs={24}>
              <Suspense fallback={null}>
                <TopSearch
                  loading={loading}
                  visitData={visitData}
                  searchData={vulnerabilityData}
                  // dropdownGroup={dropdownGroup}
                />
              </Suspense>
            </Col>

          </Row>
          <Suspense fallback={null}>
            <OfflineData
              activeKey={activeKey}
              loading={loading}
              offlineData={complianceData}
              offlineChartData={complianceChartData}
              handleTabChange={this.handleTabChange}
            />
          </Suspense>
        </React.Fragment>
      </GridContent>
    );
  }
}

export default Analysis;
