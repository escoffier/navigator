import { queryImageDetail } from './service';

const Model = {
  namespace: 'image',
  state: {
    detail: {},
    vulns: [],
    files: [],
    commands: [],
    packages: [],
  },

  effects: {
    *fetchDetail({ payload }, { call, put }) {
      const { detail } = yield call(queryImageDetail, { query: 'detail', id: payload });
      yield put({
        type: 'save',
        payload: {
          detail: detail || {},
        },
      });
    },
    *fetchVulns({ payload }, { call, put }) {
      const { vulns } = yield call(queryImageDetail, { query: 'vulns', id: payload });
      yield put({
        type: 'save',
        payload: {
          vulns: vulns || [],
        },
      });
    },
    *fetchFiles({ payload }, { call, put }) {
      const { files } = yield call(queryImageDetail, { query: 'files', id: payload });
      yield put({
        type: 'save',
        payload: {
          files: files || [],
        },
      });
    },
    *fetchCommands({ payload }, { call, put }) {
      const { commands } = yield call(queryImageDetail, { query: 'history', id: payload });
      yield put({
        type: 'save',
        payload: {
          commands: commands || [],
        },
      });
    },

    *fetchPackages({ payload }, { call, put }) {
      const { packages } = yield call(queryImageDetail, { query: 'packages', id: payload });
      yield put({
        type: 'save',
        payload: {
          packages: packages || [],
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
        vulns: [],
        files: [],
        commands: [],
        packages: [],
      };
    },
  },
};
export default Model;
