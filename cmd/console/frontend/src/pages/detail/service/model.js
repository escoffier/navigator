import { queryServiceDetail } from './service';

const Model = {
  namespace: 'service',
  state: {
    detail: {},
    inbound: [],
    outbound: [],
  },

  effects: {
    *fetchDetail({ payload }, { call, put }) {
      const { detail } = yield call(queryServiceDetail, { query: 'detail', id: payload });
      yield put({
        type: 'save',
        payload: {
          detail: detail || {},
        },
      });
    },
    *fetchInbound({ payload }, { call, put }) {
      const { inbound } = yield call(queryServiceDetail, { query: 'inbound', id: payload });
      yield put({
        type: 'save',
        payload: {
          inbound: inbound || [],
        },
      });
    },
    *fetchOutbound({ payload }, { call, put }) {
      const { outbound } = yield call(queryServiceDetail, { query: 'outbound', id: payload });
      yield put({
        type: 'save',
        payload: {
          outbound: outbound || [],
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
        inbound: [],
        outbound: [],
      };
    },
  },
};
export default Model;
