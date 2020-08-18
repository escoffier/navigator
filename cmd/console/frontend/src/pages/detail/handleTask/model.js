import { queryHandleTask, postHandleTask } from './service';

const Model = {
  namespace: 'handleTask',
  state: {
    data: {
      handlers: [],
      users: [],
    },
  },
  effects: {
    *fetch({ payload }, { call, put }) {
      const response = yield call(queryHandleTask, payload);
      yield put({
        type: 'save',
        payload: response,
      });
    },

    *add({ payload }, { call, put }) {
      const response = yield call(postHandleTask, payload);
      yield put({
        type: 'save',
        payload: response,
      });
    },
  },
  reducers: {
    save(state, action) {
      return { ...state, data: action.payload };
    },
  },
};
export default Model;
