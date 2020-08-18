import { postCluster } from './service';
import {notification} from "antd";

const Model = {
  namespace: 'configClusterCreate',
  state: {
    rule: {},
    validated: false,
    message: "",
  },

  effects: {
    *create({ payload }, { call, put }) {
      const response = yield call(postCluster, payload);
      if (response.status && response.status !== 200) {
        response.json().then(function(body) {
          notification.error({
            message: "请求错误",
            description: body.error,
          });
        });
      } else {
        yield put({ type: 'save', payload: {message: response.message} })
      }
    },
  },

  reducers: {
    save(state, { payload }) {
      return { ...state, validated: true, message: payload.message };
    },

    clear() {
      return {
        rule: {},
        validated: false,
        msg: "",
      };
    },
  },
};
export default Model;
