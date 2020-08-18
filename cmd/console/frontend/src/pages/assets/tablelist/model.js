import { queryNodeContainers, queryNode} from './service';

const Model = {
  namespace: 'assetsAndtablelist',
  state: {
    data: {
      list: [],
      pagination: {},
    },
    nodes: {
      list: [],
    },
  },
  effects: {
    *fetch({ payload }, { call, put }) {
      const response = yield call(queryNode, payload);
      yield put({
        type: 'saveNodes',
        payload: response,
      });
    },

    *fetchContainers({ payload, callback }, { call, put }) {
      const response = yield call(queryNodeContainers, payload);
      yield put({
        type: 'save',
        payload: response,
      });
      if (callback) callback();
    },
  },
  reducers: {
    save(state, action) {
      return { ...state, data: action.payload };
    },
    saveNodes(state, action) {
      return { ...state, nodes: action.payload };
    },
  },
};
export default Model;
