import { queryTags, queryVulns } from './service';

const Model = {
  namespace: 'alertsAndvulnerabilities',
  state: {
    tags: [],
    vulns: [],
  },
  effects: {
    *fetchTags(_, { call, put }) {
      const response = yield call(queryTags);
      yield put({
        type: 'saveTags',
        payload: response.list,
      });
    },
    *fetchVulns(_, { call, put }) {
      const response = yield call(queryVulns);
      yield put({
        type: 'saveVulns',
        payload: response.list,
      });
    },
  },
  reducers: {
    saveTags(state, action) {
      return { ...state, tags: action.payload };
    },
    saveVulns(state, action) {
      return { ...state, vulns: action.payload };
    },
  },
};
export default Model;
