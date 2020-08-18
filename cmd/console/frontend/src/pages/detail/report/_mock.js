import { parse } from 'url';

function getFakeHandlers(req, res, u) {
  const result = {
    detail: {
      name: `Docker 扫描`,
      entities: [{'name': '主机0'},{'name': '主机0'},{'name': '主机0'}],
      created: '2019-10-13 00:00:01',
      finished: '2019-10-13 00:01:01',
      owner: '管理员',
      status: Math.floor(Math.random() * 10) % 2,
      total: 10,
      critical: 8,
    },
  }

  return res.json(result)
}

export default {
  'GET /api/v1/detail/report': getFakeHandlers,
};
