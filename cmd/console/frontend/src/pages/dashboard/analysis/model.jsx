import { chartData } from './service';

const initState = {
  visitData: [],
  allTimeData: [],
  vulnerabilityData: [],
  complianceData: [],
  complianceChartData: [],
  alertsDistDataHost: [],
  alertsDistDataContainer: [],
  alertsDistDataCluster: [],
  severityVulnerabilityData: [],
  severityAlertData: [],
  severityCheckData: [],
  rankingListData: [],
};

const Model = {
  namespace: 'dashboardAndanalysis',
  state: initState,
  effects: {
    *fetch(_, { call, put }) {
      const response = yield call(chartData);
      yield put({
        type: 'save',
        payload: response,
      });
    },

    *fetchSalesData({ payload: { start, end } }, { call, put }) {
      const response = yield call(chartData, start, end);
      yield put({
        type: 'save',
        payload: {
          salesData: response.salesData,
        },
      });
    },
  },
  reducers: {
    save(state, { payload }) {
      return { ...state, ...payload };
    },

    clear() {
      return initState;
    },
  },
};
export default Model;
