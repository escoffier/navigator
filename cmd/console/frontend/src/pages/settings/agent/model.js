import { queryClusters, queryAgents, deleteCluster } from './service';
import {notification} from "antd";

const Model = {
  namespace: 'settingsAndagent',
  state: {
    clusters: [],
    agents: [],
    deleted: false,
  },
  effects: {
    *fetch(_, { call, put }) {
      const response = yield call(queryClusters);
      yield put({
        type: 'save',
        payload: response.clusters,
      });
    },
    *fetchAgents(_, { call, put }) {
      const response = yield call(queryAgents);
      yield put({
        type: 'saveAgents',
        payload: response.agents,
      });
    },

    *deleteAgent( { payload }, { call, put }) {
      console.log(payload)
    },

    *deleteCluster( { payload }, { call, put }) {
      const response = yield call(deleteCluster, payload);
      if (response.status && response.status !== 200) {
        response.json().then(function(body) {
          notification.error({
            message: "请求错误",
            description: body.error,
          });
        });
      } else {
        yield put({ type: 'saveDelete', payload: {message: response.message} })
        notification.info({
          message: "请求成功",
          description: response.message,
        });
        yield call(queryClusters)
      }
    },
  },

  reducers: {
    save(state, action) {
      return { ...state, clusters: action.payload || [] } ;
    },
    saveAgents(state, action) {
      return { ...state, agents: action.payload || [] } ;
    },
    saveDelete(state, { payload }) {
      return { ...state, deleted: true, message: payload.message}
    }
  },
};

export default Model;
