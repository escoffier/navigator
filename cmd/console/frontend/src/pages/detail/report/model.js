import { queryReportDetail } from './service';

const Model = {
  namespace: 'reportAndDetail',
  state: {
    detail: {},
  },
  effects: {
    *fetch({ payload }, { call, put }) {
      const response = yield call(queryReportDetail, payload);
      yield put({
        type: 'save',
        payload: response.detail,
      });
    },
  },
  reducers: {
    save(state, action) {
      return { ...state, detail: action.payload };
    },
  },
};
export default Model;
