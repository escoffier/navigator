import { queryAssetsList } from './service';

const Model = {
  namespace: 'assetsAndclusters',
  state: {
    data: {
      list: [],
      pagination: {},
    }
  },

  effects: {
    *fetch({ payload }, { call, put }) {
      const response = yield call(queryAssetsList, payload);
      yield put({
        type: 'queryList',
        payload: response ? response : {},
      });
    },
  },

  reducers: {
    queryList(state, action) {
      return { ...state, data: action.payload };
    },
  },
};
export default Model;
