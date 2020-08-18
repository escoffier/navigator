import { postRule, getRuleForm } from './service';

const Model = {
  namespace: 'rule',
  state: {
    rule: {},
    formData: {},
  },

  effects: {
    *create({ payload }, { call, put }) {
      const { detail } = yield call(postRule, {data: payload });
      yield put({
        type: 'save',
        payload: {
          rule: detail || {},
        },
      });
    },
    *fetch( { payload }, {call, put}) {
      const { formData } = yield call(getRuleForm, payload);
      yield put({
        type: 'save',
        payload: {
          formData: formData || {},
        },
      })
    },
  },
  reducers: {
    save(state, { payload }) {
      return { ...state, ...payload };
    },
    clear() {
      return {
        rule: {},
        formData: {},
      };
    },
  },
};
export default Model;
