import { queryReports, queryReportDetail,  queryReportProblems} from './service';

const Model = {
  namespace: 'alertsAndreports',
  state: {
    reports: [],
    problems: [],
  },
  effects: {
    *fetchReports(_, { call, put }) {
      const response = yield call(queryReports);
      yield put({
        type: 'saveReports',
        payload: response.list,
      });
    },
    *fetchReportDetail({ payload }, { call, put }) {
      const response = yield call(queryReports, payload);
      yield put({
        type: 'saveReports',
        payload: response.list,
      });
    },
    *fetchReportProblems(_, {call, put}) {
      const response = yield call(queryReportProblems);
      yield put({
        type: 'saveProblems',
        payload: response.list
      })
    }
  },
  reducers: {
    saveReports(state, action) {
      return { ...state, reports: action.payload };
    },

    saveProblems(state, action) {
      return { ...state, problems: action.payload };
    },
  },
};
export default Model;
