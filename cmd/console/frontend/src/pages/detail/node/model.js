import { queryNodeDetail } from './service';

const Model = {
  namespace: 'node',
  state: {
    detail: {},
    logs: [],
    reports: [],
    containers: [],
  },

  effects: {
    *fetchDetail({ payload }, { call, put }) {
      const { detail } = yield call(queryNodeDetail, { query: 'detail', id: payload });
      yield put({
        type: 'save',
        payload: {
          detail: detail || {},
        },
      });
    },
    *fetchLog({ payload }, { call, put }) {
      const { logs } = yield call(queryNodeDetail, { query: 'logs', id: 0, vulns: payload.vulns, date: payload.date });
      yield put({
        type: 'save',
        payload: {
          logs: logs || [],
        },
      });
    },
    *fetchReport({ payload }, { call, put }) {
      const { reports } = yield call(queryNodeDetail, { query: 'reports', id: payload });
      yield put({
        type: 'save',
        payload: {
          reports: reports || [],
        },
      });
    },
    *fetchContainer({ payload }, { call, put }) {
      const { containers } = yield call(queryNodeDetail, { query: 'containers', id: payload });
      yield put({
        type: 'save',
        payload: {
          containers: containers || [],
        },
      });
    },
  },
  reducers: {
    save(state, { payload }) {
      return { ...state, ...payload };
    },
    clear() {
      return {
        detail: {},
        logs: [],
        reports: [],
        containers: [],
      };
    },
  },
};
export default Model;
