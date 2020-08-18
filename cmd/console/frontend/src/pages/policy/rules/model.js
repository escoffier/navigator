import { queryRulesList } from './service';

const Model = {
  namespace: 'policyAndrules',
  state: {
    list: [],
  },
  effects: {
    *fetch({ payload }, { call, put }) {
      const response = yield call(queryRulesList, payload);
      yield put({
        type: 'save',
        payload: Array.isArray(response) ? response : [],
      });
    },
  },
  reducers: {
    save(state, action) {
      return { ...state, list: action.payload };
    },
  },
};
export default Model;
