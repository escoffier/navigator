import moment from 'moment';
// mock data

const  visitData = [];
const beginDay = new Date().getTime();

const fakeY = [1, 6, 4, 8, 3, 7, 2];

for (let i = 0; i < fakeY.length; i += 1) {
  visitData.push({
    x: moment(new Date(beginDay + 1000 * 60 * 60 * 24 * i)),
    y: fakeY[i],
  });
}

const salesAllData = [];

for (let i = 0; i < 12; i += 1) {
  salesAllData.push({
    x: `${i + 1}月`,
    y: Math.floor(Math.random() * 1000) + 200,
  });
}

const salesCriticalData = [];

for (let i = 0; i < 12; i += 1) {
  salesCriticalData.push({
    x: `${i + 1}月`,
    y: Math.floor(Math.random() * 1000) + 200,
  });
}

const allTimeData = {
  'all': salesAllData,
  'critical': salesCriticalData,
};

const vulnerabilityData = [];

for (let i = 0; i < 50; i += 1) {
  vulnerabilityData.push({
    index: i + 1,
    keyword: `CVE-2019-00${i}`,
    count: Math.floor(Math.random() * 1000),
    range: Math.floor(Math.random() * 100),
    status: Math.floor((Math.random() * 10) % 2),
  });
}

const alertsDistDataHost = [
  {
    x: '规则1',
    y: 4,
  },
  {
    x: '规则2',
    y: 1,
  },
  {
    x: '规则3',
    y: 3,
  },
  {
    x: '规则4',
    y: 2,
  },
  {
    x: '规则5',
    y: 12,
  },
  {
    x: '其他',
    y: 3,
  },
];
const alertsDistDataContainer = [
  {
    x: '规则6',
    y: 4,
  },
  {
    x: '规则7',
    y: 3,
  },
  {
    x: '规则8',
    y: 7,
  },
  {
    x: '规则9',
    y: 3,
  },
  {
    x: '规则10',
    y: 2,
  },
  {
    x: '其他',
    y: 1,
  },
];
const alertsDistDataCluster = [
  {
    x: '规则11',
    y: 9,
  },
  {
    x: '规则12',
    y: 1,
  },
  {
    x: '规则13',
    y: 3,
  },
  {
    x: '规则14',
    y: 2,
  },
  {
    x: '其他',
    y: 5,
  },
];
const complianceData = [];

for (let i = 0; i < 10; i += 1) {
  complianceData.push({
    name: `检查 ${i}`,
    cvr: Math.ceil(Math.random() * 9) / 10,
  });
}

const complianceChartData = [];

for (let i = 0; i < 20; i += 1) {
  complianceChartData.push({
    x: new Date().getTime() + 1000 * 60 * 30 * i,
    y1: Math.floor(Math.random() * 100) + 10,
    y2: Math.floor(Math.random() * 100) + 10,
  });
}

const severityVulnerabilityData = [
  {x: '严重', y: 5, category: 'critical'},
  {x: '中等', y: 10, category: 'medium'},
  {x: '轻度', y: 5, category: 'low'},
];

const severityAlertData = [
  {x: '严重', y: 15, category: 'critical'},
  {x: '警告', y: 35, category: 'medium'},
  {x: '信息', y: 16, category: 'low'},
];


const severityCheckData = [
  {x: '检查1', y: 85, category: 'low'},
  {x: '检查2', y: 65, category: 'medium'},
  {x: '检查3', y: 60, category: 'critical'},
  {x: '检查4', y: 85, category: 'low'},
  {x: '检查5', y: 65, category: 'medium'},
  {x: '检查6', y: 60, category: 'critical'},
  {x: '检查7', y: 85, category: 'low'},
  {x: '检查8', y: 65, category: 'medium'},
  {x: '检查9', y: 60, category: 'critical'},
  {x: '检查10', y: 85, category: 'low'},
  {x: '检查11', y: 65, category: 'medium'},
  {x: '检查12', y: 60, category: 'critical'},
  {x: '检查13', y: 85, category: 'low'},
  {x: '检查14', y: 65, category: 'medium'},
  {x: '检查15', y: 60, category: 'critical'},
];

const rankingListData = [];

for (let i = 0; i < 7; i += 1) {
  rankingListData.push({
    title: "container " + i,
    value: 323 - i * 13,
  });
}

const getFakeChartData = {
  visitData,
  allTimeData,
  vulnerabilityData,
  complianceData,
  complianceChartData,
  alertsDistDataHost,
  alertsDistDataContainer,
  alertsDistDataCluster,
  severityVulnerabilityData,
  severityAlertData,
  severityCheckData,
  rankingListData,
};

export default {
  'GET  /api/v1/overall/analysis_chart': getFakeChartData,
};
