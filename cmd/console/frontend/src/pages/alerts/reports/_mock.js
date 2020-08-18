// export default {
//   'GET /api/v1/vulnerabilities/tags': mockjs.mock({
//     'list|100': [
//       {
//         name: '@city',
//         'value|1-100': 150,
//         'type|0-2': 1,
//       },
//     ],
//   }),
// };


function fixedZero(val) {
  return val * 1 < 10 ? `0${val}` : val;
}

function fakeHotMapList() {
  const list = [];
  for (let i = 0; i < 100; i += 1) {
    list.push({
      name: `cve-2019-00${fixedZero(i)}`,
      value: Math.ceil(Math.random() * 50) + 50,
      type: i % 2,
    });
  }

  return list
}

function fakeReports() {
  const list = [];
  for (let i = 0; i < 28; i += 1) {
    list.push({
      key: i,
      name: ['docker 合规扫描', '主机合规扫描', 'Kuberentes合规'][i % 3],
      severity: i % 4,
      total: Math.ceil(Math.random() * 50),
      critical: Math.ceil(Math.random() * 20),
      finished: new Date(),
      created: new Date(),
    })
  }

  return list
}

function fakeProblems() {
  const list = [];
  for (let i = 0; i < 28; i += 1) {
    list.push({
      key: i,
      name: ['docker 合规扫描', '主机合规扫描', 'Kuberentes合规'][i % 3],
      description: '确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)',
      result: 0,
      critical: Math.ceil(Math.random() * 20) % 3,
      complianceHost: [{name: '主机0', lnk: '/detail/node/0'}, {name: '主机1', lnk: '/detail/node/1'}],
      handle: "If using a Kubelet config file, " +
          "edit the file to set authentication: x509: clientCAFile to\n " +
          "the location of the client CA file.\nIf using command line arguments, " +
          "edit the kubelet service file\n$kubeletsvc on each worker node and\n" +
          "set the below parameter in KUBELET_AUTHZ_ARGS variable.\n " +
          "--client-ca-file=<path/to/client-ca-file>\n" +
          "Based on your system, restart the kubelet service. For example:\n" +
          "systemctl daemon-reload\n" +
          "systemctl restart kubelet.service"
    })
  }

  return list
}


export default {
  'GET /api/v1/alarms/report': {
    list: fakeHotMapList(),
  },

  'GET /api/v1/alarms/reports': {
    list: fakeReports(),
  },

  'GET /api/v1/alarms/reports/problems': {
    list: fakeProblems(),
  },
};
