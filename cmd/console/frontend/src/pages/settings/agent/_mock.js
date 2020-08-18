import city from './geographic/city.json';
import province from './geographic/province.json';

function getProvince(_, res) {
  return res.json(province);
}

function getCity(req, res) {
  return res.json(city[req.params.province]);
} // 代码中会兼容本地 service mock 以及部署站点的静态数据

const clusters = [
  {
    key: 0,
    name: '集群1',
    account: 'admin',
    category: 'Kubernetes',
    credential: '*******',
    serviceAccount: 'prod',
    serviceRole: 'clusteradmin',
    total: 3,
    agents: [{
      key: 1,
      name: 'd1',
      status: 0,
      category: 'daemontset',
    }, {
      key: 2,
      name: 'd2',
      category: 'daemontset',
      status: 0,
    }, {
      key: 3,
      name: 's1',
      category: 'sidecar',
      status: 1,
    }],
  },
  {
    key: 1,
    name: '集群2',
    account: 'developer',
    category: 'Openshift',
    credential: '*******',
    serviceAccount: 'dev',
    serviceRole: 'viewer',
    total: 3,
    agents: [{
      key: 1,
      name: 'o1',
      category: 'daemontset',
      status: 0,
    }, {
      key: 2,
      name: 'o2',
      category: 'daemontset',
      status: 0,
    }, {
      key: 3,
      name: 's1',
      category: 'sidecar',
      status: 0,
      }],
    },
  {
    key: 2,
    name: '集群3',
    account: 'developer',
    category: 'Kubernetes',
    credential: '*******',
    serviceAccount: 'dev',
    serviceRole: 'viewer',
    total: 3,
    agents: [{
      key: 1,
      name: 'd4',
      category: 'daemontset',
      status: 0,
    }, {
      key: 2,
      name: 'd5',
      category: 'sidecar',
      status: 0,
    }, {
      key: 3,
      name: 's2',
      category: 'sidecar',
      status: 0,
    }],
  },
];

const agents = [
  {
    key: 0,
    id: 'd1',
    name: 'd1',
    type: 'daemonset',
    status: 0,
    lastUpdated: new Date(),
    parent: {
      key: 0,
      name: '集群1',
      type: 'cluster',
    },
  },
  {
    key: 1,
    id: 'd2',
    name: 'd2',
    type: 'sidecar',
    status: 0,
    lastUpdated: new Date(),
    parent: {
      key: 0,
      name: '集群1',
      type: 'cluster',
    },
  },
  {
    key: 2,
    id: 'scanner1',
    name: 'scanner1',
    type: 'image scanner',
    status: 1,
    lastUpdated: new Date(),
    parent: {
      key: 1,
      name: 'scanner-1',
      type: 'k8s-deployment',
    },
  },
  {
    key: 3,
    id: 'compliance1',
    name: 'compliance1',
    type: 'compliance checker',
    status: 0,
    lastUpdated: new Date(),
    parent: {
      key: 2,
      name: 'cis-scap-1',
      type: 'k8s-deployment',
    },
  },
  {
    key: 4,
    id: 'd3',
    name: 'd3',
    type: 'docker agent',
    status: 1,
    lastUpdated: new Date(),
    parent: {
      key: 4,
      name: 'docker',
      type: 'docker node',
    },
  },
];

function getClusters(req, res) {
  return res.json({clusters})
}

function getAgents(req, res) {
  return res.json({agents}  )
}

function postAgents(req, res) {
  let url = u;

  if (!url || Object.prototype.toString.call(url) !== '[object String]') {
    // eslint-disable-next-line prefer-destructuring
    url = req.url;
  }

  const body = (b && b.body) || req.body;
  const { method, name, desc, key } = body;

  switch (method) {
    case 'post':
      break;
  }
}

export default {
  'GET  /api/v1/config/clusters': getClusters,
  'GET  /api/v1/config/agents': getAgents,
  'DELETE /api/v1/config/cluster/:clusterId': (req, res) => {
      if  (req.params.clusterId) {
        console.log(req.params.clusterId)
        res.status(200).json({"message": `成功删除${req.params.clusterId}`})
      } else {
        res.status(500).json({"error": "失败"})
      }
  },
  'DELETE /api/v1/config/agent/:agentId': (req, res) => {
    if  (req.params.agentId) {
      console.log(req.params.agentId)
      res.status(200).json({"message": `成功删除${req.params.clusterId}`})
    } else {
      res.status(500).json({"error": "失败"})
    }
  },
};
