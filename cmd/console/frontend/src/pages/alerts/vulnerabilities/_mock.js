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

function fakeVulnerabilities() {
  const list = [];
  for (let i = 0; i < 97; i += 1) {
    list.push({
      key: i,
      name: `cve-2019-00${fixedZero(i)}`,
      severity: i % 4,
      recent: i % 2,
      inWhite: false,
      cvss2: `${(Math.ceil(Math.random() * 50)) % 10}.0`,
      cvss3: `${(Math.ceil(Math.random() * 50)) % 10}.0`,
      component: `ubuntu: 16.04/apt: ${i}.0.0`,
      updated: new Date(),
      lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946',
      solved: (Math.ceil(Math.random() * 50)) % 2 === 0,
      inProduction: (Math.ceil(Math.random() * 50)) % 2 === 0,
      networkExploitable: (Math.ceil(Math.random() * 50)) % 4 === 0,
      hostPrivilege: (Math.ceil(Math.random() * 50)) % 5 === 0,
      criticalRecent: (Math.ceil(Math.random() * 50)) % 3 === 0,
      description: `此漏洞为cve-2019-00${fixedZero(i)}`,
      evalScore: Math.ceil(Math.random() * 100),
      affectImages: [1, 2, 3],
      affectContainers: [1, 2, 4],
      affectHosts: [1, 2, 3],
    })
  }

  return list
}


export default {
  'GET /api/v1/alarms/vulnerabilities/tags': {
    list: fakeHotMapList(),
  },

  'GET /api/v1/alarms/vulnerabilities': {
    list: fakeVulnerabilities(),
  },
};
