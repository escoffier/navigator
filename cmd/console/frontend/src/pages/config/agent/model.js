import { postAgent } from './service';

const Model = {
  namespace: 'configAgentCreate',
  state: {
    rule: {},
  },

  effects: {
    *create({ payload }, { call, put }) {
      const { detail } = yield call(postAgent, payload);
      yield put({
        type: 'save',
        payload: {
          rule: detail || {},
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
        rule: {},
      };
    },
  },
};
export default Model;
