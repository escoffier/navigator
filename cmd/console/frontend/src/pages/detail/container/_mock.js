import { parse } from 'url';

const sourceData = [];

function getFakeContainer(req, res, u) {
  const params = req.query;
  const { query, id } = params;
  let result = {};

  let url = u;

  if (!url || Object.prototype.toString.call(url) !== '[object String]') {
    // eslint-disable-next-line prefer-destructuring
    url = req.url;
  }

  const queryParams = JSON.parse(parse(url, true).query.id);
  const name = queryParams.category || 1;
  if (query === 'detail') {
      result = {
        detail: {
          name: `Container ${name}`,
          image: { key: '0', name: 'image1' },
          created: '2019-10-13 00:00:01',
          updated: '2019-10-13 00:01:01',
          owner: '管理员',
          namespace: 'DEV',
          tags: ['DEVELOPMENT', 'ARKSEC'],
          status: Math.floor(Math.random() * 10) % 3,
          total: Math.floor(Math.random() * 10),
        },
      }
  } else if (query === 'logs') {
      const origData = [
        { name: 'logs_test_0', key: 'log_0', severity: 0, category: 0, details: [0, 1, 2], desc: 'the web shell is detected', createdAt: '2019-10-13 00:00:01' },
        { name: 'logs_test_1', key: 'log_1', severity: 1, category: 1, details: [0], desc: 'find one web invalid visit', createdAt: '2019-10-13 00:01:01' },
        { name: 'logs_test_2', key: 'log_2', severity: 2, category: 2, details: [1], desc: 'abnormal process is started', createdAt: '2019-10-13 00:02:01' },
        { name: 'logs_test_3', key: 'log_3', severity: 0, category: 0, details: [0, 1, 2], desc: 'the web shell is detected', createdAt: '2019-10-14 00:00:01' },
        { name: 'logs_test_4', key: 'log_4', severity: 1, category: 1, details: [0], desc: 'find one web invalid visit', createdAt: '2019-10-14 00:01:01' },
        { name: 'logs_test_5', key: 'log_5', severity: 2, category: 2, details: [1], desc: 'abnormal process is started', createdAt: '2019-10-14 00:02:01' },
      ];

      let filteredData = origData;

      if (queryParams.category) {
        filteredData = filteredData.filter(
          data => data.category === parseInt(queryParams.category, 10),
        );
      }

      if (queryParams.severity) {
        filteredData = filteredData.filter(
          data => data.severity === parseInt(queryParams.severity, 10),
        );
      }

      result = {
        logs: filteredData,
      }
  } else if (query === 'reports') {
    result = {
      reports: [{ name: 'reports_test_0', key: 'report_0', created: '2019-10-13 00:00:01' },
      { name: 'reports_test_1', key: 'report_1', created: '2019-10-13 00:01:01' },
      { name: 'reports_test_2', key: 'report_2', created: '2019-10-13 00:02:01' }],
    }
  } else if (query === 'alerts') {
    result = {
      alerts: [{ name: 'alerts_test_0', key: 'alert_0', created: '2019-10-13 00:00:01' },
      { name: 'alerts_test_1', key: 'alert_1', created: '2019-10-13 00:01:01' },
      { name: 'alerts_test_2', key: 'alert_2', created: '2019-10-13 00:02:01' }],
    }
  }

  return res.json(result);
}


function postFakeList(req, res) {
  const {
    /* url = '', */
    body,
  } = req; // const params = getUrlParams(url);

  const { method, id } = body; // const count = (params.count * 1) || 20;

  let result = sourceData || [];

  switch (method) {
    case 'delete':
      result = result.filter(item => item.id !== id);
      break;

    case 'update':
      result.forEach((item, i) => {
        if (item.id === id) {
          result[i] = { ...item, ...body };
        }
      });
      break;

    case 'post':
      result.unshift({
        ...body,
        id: `fake-list-${result.length}`,
        createdAt: new Date().getTime(),
      });
      break;

    default:
      break;
  }

  return res.json(result);
}

export default {
  'GET /api/v1/detail/container': getFakeContainer,
};
