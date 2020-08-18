const sourceData = [];

function getFakeContainer(req, res) {
  const params = req.query;
  const { query, id } = params;
  let result = {};

  if (query === 'detail') {
    result = {
      detail: {
        name: `Container ${id}`,
        image: { key: '100', name: 'image1' },
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
    result = {
      logs: [{ name: 'logs_test_8', key: 'log_0', created: '2019-10-13 00:00:01' },
      { name: 'logs_test_6', key: 'log_1', created: '2019-10-13 00:01:01' },
      { name: 'logs_test_7', key: 'log_2', created: '2019-10-13 00:02:01' }],
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

function getFakeFormData(req, res) {
  const params = req.query;
  const { cate } = params;

  let formData = {param: params};
  if (cate === 'host') {
    formData = {
      agents: [
        'd1-daemonset',
        'd2-sidecar',
      ],
      objs: [
        {
          name: 'Pod容器',
          key: 'c-1',
          nodes: [
            { name: '容器1', key: 'c-1-0' },
            { name: '容器2', key: 'c-1-1' },
            { name: '容器3', key: 'c-1-2' },
            { name: '容器4', key: 'c-1-3' },
            { name: '容器5', key: 'c-1-4' },
            { name: '容器6', key: 'c-1-5' },
            { name: '容器4', key: 'c-1-6' },
            { name: '容器5', key: 'c-1-7' },
            { name: '容器6', key: 'c-1-8' },
          ],
        }, {
          name: '标签',
          key: 't-1',
          nodes: [
            { name: 'arksec.io/install', key: 't-1-0' },
            { name: 'helm.chart/install', key: 't-1-1' },
            { name: 'develop', key: 't-1-2' },
          ],
        }, {
          name: '节点',
          key: 'n-1',
          nodes: [
            { name: '节点1', key: 'n-1-0' },
            { name: '节点2', key: 'n-1-1' },
          ],
        },
      ],
      rules: [
        {key: 0, title: '拒绝服务攻击', chosen: false},
        {key: 1, title: 'Webshell检测', chosen: false},
        {key: 2, title: '本地提权', chosen: false},
        {key: 3, title: 'SQL嵌入攻击', chosen: false},
        {key: 4, title: '自动化异常进程', chosen: false},
        {key: 5, title: '关键文件夹监测', chosen: false},
        {key: 6, title: '可执行文件病毒扫描', chosen: false},
        {key: 7, title: '数据隐私性保护', chosen: false},
        {key: 8, title: 'Fork炸弹', chosen: false},
        {key: 9, title: '路径遍历攻击', chosen: false},
        {key: 10, title: '本地缓冲区溢出', chosen: false},
        {key: 11, title: '堆栈溢出', chosen: false},
        {key: 12, title: '堆栈发散攻击Spray', chosen: false},
        {key: 13, title: '木马后门检测', chosen: false},
        {key: 14, title: '黑白名单网络隔离', chosen: false},
        {key: 15, title: '应用层防火墙WAF', chosen: false},
        {key: 16, title: '自定义Log搜索检测', chosen: false},
      ],
    }
  } else if (cate === 'docker') {
    formData = {
      agents: [
        'd1-docker-container',
      ],
      objs: [
        {
          name: '容器',
          key: 'c-1',
          nodes: [
            { name: 'Docker容器1', key: 'c-1-0' },
            { name: 'Docker容器2', key: 'c-1-1' },
            { name: 'Docker容器3', key: 'c-1-2' },
            { name: 'Docker容器4', key: 'c-1-3' },
            { name: 'Docker容器5', key: 'c-1-4' },
            { name: 'Docker容器6', key: 'c-1-5' },
          ],
        }, {
          name: '标签',
          key: 't-1',
          nodes: [
            { name: 'docker.io/install', key: 't-1-0' },
            { name: 'develop', key: 't-1-1' },
          ],
        },
      ],
      rules: [
        {key: 0, title: '拒绝服务攻击', chosen: false},
        {key: 1, title: 'Webshell检测', chosen: false},
        {key: 2, title: '本地提权', chosen: false},
        {key: 3, title: 'SQL嵌入攻击', chosen: false},
        {key: 4, title: '自动化异常进程', chosen: false},
        {key: 5, title: '关键文件夹监测', chosen: false},
        {key: 6, title: '可执行文件病毒扫描', chosen: false},
        {key: 7, title: '数据隐私性保护', chosen: false},
        {key: 8, title: 'Fork炸弹', chosen: false},
        {key: 9, title: '路径遍历攻击', chosen: false},
        {key: 10, title: '本地缓冲区溢出', chosen: false},
        {key: 11, title: '堆栈溢出', chosen: false},
        {key: 12, title: '堆栈发散攻击Spray', chosen: false},
        {key: 13, title: '木马后门检测', chosen: false},
        {key: 14, title: '黑白名单网络隔离', chosen: false},
        {key: 15, title: '应用层防火墙WAF', chosen: false},
        {key: 16, title: '自定义Log搜索检测', chosen: false},
      ],
    }
  } else if (cate === 'monitor') {
    formData = {
      agents: [
        'd1-daemonset',
        'd2-sidecar',
      ],
      objs: [
        {
          name: 'Pod容器',
          key: 'c-1',
          nodes: [
            { name: '容器1', key: 'c-1-0' },
            { name: '容器2', key: 'c-1-1' },
            { name: '容器3', key: 'c-1-2' },
            { name: '容器4', key: 'c-1-4' },
            { name: '容器5', key: 'c-1-7' },
            { name: '容器6', key: 'c-1-8' },
          ],
        }, {
          name: '标签',
          key: 't-1',
          nodes: [
            { name: 'arksec.io/install', key: 't-1-0' },
            { name: 'helm.chart/install', key: 't-1-1' },
            { name: 'develop', key: 't-1-2' },
          ],
        }, {
          name: '节点',
          key: 'n-1',
          nodes: [
            { name: '节点1', key: 'n-1-0' },
            { name: '节点2', key: 'n-1-1' },
          ],
        },
      ],
      rules: [
        {key: 0, title: '黑白名单网络隔离', chosen: false},
        {key: 1, title: '拒绝服务攻击', chosen: false},
        {key: 2, title: 'Webshell检测', chosen: false},
        {key: 3, title: '检测SQL嵌入攻击', chosen: false},
        {key: 4, title: '应用层防火墙WAF', chosen: false},
        {key: 16, title: '自定义Log搜索检测', chosen: false},
      ],
    }
  } else if (cate === 'dpi') {
    formData = {
      agents: [
        'd1-daemonset',
        'd2-sidecar',
      ],
      rules: [
        {key: 0, title: '拒绝服务攻击', chosen: false},
        {key: 1, title: 'Webshell检测', chosen: false},
        {key: 2, title: 'SQL嵌入攻击', chosen: false},
        {key: 3, title: '自动化异常流量检测', chosen: false},
        {key: 16, title: '自定义Log搜索检测', chosen: false},
      ]
    }
  } else if (cate === 'image') {
    formData = {
      agents: [
        'scanner-1',
      ],
      objs: [
        {
          name: 'NVD',
          key: 'cis-1',
        }, {
          name: 'CNNVD',
          key: 't-1',
        },
      ],
      rules: [
        {key: 0, title: '黑白名单漏洞检测', chosen: false},
        {key: 1, title: '无差别漏洞检测', chosen: false},
        {key: 2, title: '可执行文件完整性', chosen: false},
        {key: 3, title: '可执行文件病毒扫描', chosen: false},
        {key: 4, title: '数据隐私性保护', chosen: false},
        {key: 5, title: '检测矿机', chosen: false},
        {key: 16, title: '自定义Log搜索检测', chosen: false},
      ],
    }
  } else if (cate === 'scap') {
    formData = {
      agents: [
        'compliance-1',
      ],
      objs: [
        {
          name: 'CIS Kubernetes',
          key: 'cis-1',
        }, {
          name: 'CIS Linux',
          key: 't-1',
        }, {
          name: 'CIS Dockerbench',
          key: 'n-1',
        },
      ],
      rules: [
        {key: 0, title: '黑白名单合规检测', chosen: false},
        {key: 1, title: '无差别合规检测', chosen: false},
        {key: 16, title: '自定义Log搜索检测', chosen: false},
      ],
    }
  }

  return res.json({formData: formData});
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
  'GET /api/v1/detail/rule': getFakeContainer,
  'GET /api/v1/detail/ruleform': getFakeFormData,
  // 'POST  /api/fake_list': postFakeList,
};
