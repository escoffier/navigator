import { queryContainerDetail } from './service';

const Model = {
  namespace: 'container',
  state: {
    detail: {},
    logs: [],
    alerts: [],
    reports: [],
  },

  effects: {
    *fetchDetail({ payload }, { call, put }) {
      const { detail } = yield call(queryContainerDetail, { query: 'detail', id: payload });
      yield put({
        type: 'save',
        payload: {
          detail: detail || {},
        },
      });
    },
    *fetchLog({ payload }, { call, put }) {
      const { logs } = yield call(queryContainerDetail, { query: 'logs', id: payload });
      yield put({
        type: 'save',
        payload: {
          logs: logs || [],
        },
      });
    },
    *fetchAlert({ payload }, { call, put }) {
      const { alerts } = yield call(queryContainerDetail, { query: 'alerts', id: payload });
      yield put({
        type: 'save',
        payload: {
          alerts: alerts || [],
        },
      });
    },
    *fetchReport({ payload }, { call, put }) {
      const { reports } = yield call(queryContainerDetail, { query: 'reports', id: payload });
      yield put({
        type: 'save',
        payload: {
          reports: reports || [],
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
        alerts: [],
        reports: [],
      };
    },
  },
};
export default Model;
