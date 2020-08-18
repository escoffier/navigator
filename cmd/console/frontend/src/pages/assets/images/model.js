import { queryImage, blockImage, allowImage, scanImage } from './service';


const Model = {
  namespace: 'assetsAndimages',
  state: {
    data: {
      list: [],
      pagination: {},
    },
  },
  effects: {
    *fetch({ payload }, { call, put }) {
      const response = yield call(queryImage, payload);
      yield put({
        type: 'save',
        payload: response,
      });
    },

    *allow({ payload, callback }, { call, put }) {
      const response = yield call(allowImage, payload);
      yield put({
        type: 'save',
        payload: response,
      });
      if (callback) callback();
    },

    *block({ payload, callback }, { call, put }) {
      const response = yield call(blockImage, payload);
      yield put({
        type: 'save',
        payload: response,
      });
      if (callback) callback();
    },

    *scan({ payload, callback }, { call, put }) {
      const response = yield call(scanImage, payload);
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
  },
};

export default Model;
