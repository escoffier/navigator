import defaultSettings from './defaultSettings'; // https://umijs.org/config/

import slash from 'slash2';
import webpackPlugin from './plugin.config';
const { pwa, primaryColor } = defaultSettings; // preview.pro.ant.design only do not use in your production ;
// preview.pro.ant.design 专用环境变量，请不要在你的项目中使用它。

const { ANT_DESIGN_PRO_ONLY_DO_NOT_USE_IN_YOUR_PRODUCTION } = process.env;
const isAntDesignProPreview = ANT_DESIGN_PRO_ONLY_DO_NOT_USE_IN_YOUR_PRODUCTION === 'site';
const plugins = [
  [
    'umi-plugin-react',
    {
      antd: true,
      dva: {
        hmr: true,
      },
      locale: {
        // default false
        enable: true,
        // default zh-CN
        default: 'zh-CN',
        // default true, when it is true, will use `navigator.language` overwrite default
        baseNavigator: true,
      },
      // dynamicImport: {
      //   loadingComponent: './components/PageLoading/index',
      //   webpackChunkName: true,
      //   level: 3,
      // },
      pwa: pwa
        ? {
            workboxPluginMode: 'InjectManifest',
            workboxOptions: {
              importWorkboxFrom: 'local',
            },
          }
        : false, // default close dll, because issue https://github.com/ant-design/ant-design-pro/issues/4665
      // dll features https://webpack.js.org/plugins/dll-plugin/
      // dll: {
      //   include: ['dva', 'dva/router', 'dva/saga', 'dva/fetch'],
      //   exclude: ['@babel/runtime', 'netlify-lambda'],
      // },
    },
  ],
  [
    'umi-plugin-pro-block',
    {
      moveMock: false,
      moveService: false,
      modifyRequest: true,
      autoAddMenu: true,
    },
  ],
]; // 针对 preview.pro.ant.design 的 GA 统计代码

if (isAntDesignProPreview) {
  plugins.push([
    'umi-plugin-ga',
    {
      code: 'UA-72788897-6',
    },
  ]);
  plugins.push([
    'umi-plugin-pro',
    {
      serverUrl: 'https://ant-design-pro.netlify.com',
    },
  ]);
}

export default {
  plugins,
  block: {
    // 国内用户可以使用码云
    // defaultGitUrl: 'https://gitee.com/ant-design/pro-blocks',
    defaultGitUrl: 'https://github.com/ant-design/pro-blocks',
  },
  hash: true,
  targets: {
    ie: 11,
  },
  devtool: isAntDesignProPreview ? 'source-map' : false,
  // umi routes: https://umijs.org/zh/guide/router.html
  routes: [
    {
      path: '/user',
      component: '../layouts/UserLayout',
      routes: [
        {
          name: 'login',
          path: '/user/login',
          component: './user/login',
        },
      ],
    },
    {
      path: '/',
      component: '../layouts/SecurityLayout',
      routes: [
        {
          path: '/',
          component: '../layouts/BasicLayout',
          authority: ['admin', 'user'],
          routes: [
            {
              path: '/',
              redirect: '/dashboard/workplace',
            },
            {
              path: '/dashboard',
              name: 'overview',
              icon: 'cloud',
              routes: [
                {
                  name: 'workplace',
                  icon: 'container',
                  path: '/dashboard/workplace',
                  component: './dashboard/workplace',
                },
                {
                  name: 'analysis',
                  icon: 'environment',
                  path: '/dashboard/analysis',
                  component: './dashboard/analysis',
                },
              ],
            },
            {
              path: '/assets',
              name: 'assets',
              icon: 'appstore',
              routes: [
                {
                  name: 'cluster',
                  icon: 'cluster',
                  path: '/assets/clusters/',
                  component: './assets/clusters',
                },
                {
                  name: 'images',
                  icon: 'file-search',
                  path: '/assets/images',
                  component: './assets/images',
                },
                {
                  name: 'nodes',
                  icon: 'cloud-server',
                  path: '/assets/tablelist',
                  component: './assets/tablelist',
                },
              ],
            },
            {
              path: '/alerts',
              name: 'alerts',
              icon: 'alert',
              routes: [
                {
                  name: 'overview',
                  icon: 'monitor',
                  path: '/alerts/overview',
                  component: './alerts/overview',
                },
                {
                  name: 'vulnerabilities',
                  icon: 'safety',
                  path: '/alerts/vulnerabilities',
                  component: './alerts/vulnerabilities',
                },
                {
                  name: 'reports',
                  icon: 'ordered-list',
                  path: '/alerts/reports',
                  component: './alerts/reports',
                },
              ],
            },
            {
              path: '/logs',
              name: 'logs',
              icon: 'file',
              routes: [
                {
                  name: 'general',
                  icon: 'solution',
                  path: '/logs/general',
                  component: './logs/general',
                },
              ],
            },
            {
              path: '/policy',
              name: 'policy',
              icon: 'snippets',
              routes: [
                {
                  name: 'general',
                  icon: 'form',
                  path: '/policy/general',
                  component: './policy/general',
                },
                {
                  name: 'rules',
                  icon: 'issues-close',
                  path: '/policy/rules',
                  component: './policy/rules',
                }
              ],
            },
            {
              path: '/settings',
              name: 'settings',
              icon: 'setting',
              routes: [
                {
                  name: 'general',
                  icon: 'tool',
                  path: '/settings/general',
                  component: './settings/general',
                },
                {
                  name: 'agent',
                  icon: 'project',
                  path: '/settings/agent',
                  component: './settings/agent',
                },
                {
                  name: 'info',
                  icon: 'unordered-list',
                  path: '/settings/info',
                  component: './settings/info',
                },
              ],
            },
            {
              path: '/image/:page',
              name: 'imagedetails',
              hideInMenu: true,
              component: './image',
            },
            {
              path: '/detail',
              name: 'detail',
              hideInMenu: true,
              routes: [
                {
                  path: '/detail/pod/:container',
                  name: 'containerdetail',
                  component: './detail/container',
                },
                {
                  path: '/detail/rule/:action',
                  name: 'ruledetail',
                  component: './detail/rule',
                },
                {
                  path: '/detail/endpoint/:service',
                  name: 'servicedetail',
                  component: './detail/service',
                },
                {
                  path: '/detail/node/:node',
                  name: 'nodedetail',
                  component: './detail/node',
                },
                {
                  path: '/detail/image/:image',
                  name: 'imagedetail',
                  component: './detail/image',
                },
                {
                  path: '/detail/docker/:container',
                  name: 'dockerdetail',
                  component: './detail/docker',
                },
                {
                  path: '/detail/handletask/:task',
                  name: 'handletask',
                  component: './detail/handleTask',
                },
                {
                  path: '/detail/report/:report',
                  name: 'reportdetail',
                  component: './detail/report',
                },
              ],
            },
            {
              path: 'config',
              name: 'config',
              hideInMenu: true,
              routes: [
                {
                  path: '/config/cluster/add',
                  name: 'clusteradd',
                  component: './config/cluster',
                },
                {
                  path: '/config/cluster/query',
                  name: 'clusterview',
                  component: './config/cluster',
                },
                {
                  path: '/config/agent/add/:category',
                  name: 'agentadd',
                  component: './config/agent',
                },
              ],
            },
          ],
        },
        {
          component: './404',
        },
      ],
    },
    {
      component: './404',
    },
  ],
  // Theme for antd: https://ant.design/docs/react/customize-theme-cn
  theme: {
    'primary-color': primaryColor,
  },
  define: {
    ANT_DESIGN_PRO_ONLY_DO_NOT_USE_IN_YOUR_PRODUCTION:
      ANT_DESIGN_PRO_ONLY_DO_NOT_USE_IN_YOUR_PRODUCTION || '', // preview.pro.ant.design only do not use in your production ; preview.pro.ant.design 专用环境变量，请不要在你的项目中使用它。
  },
  ignoreMomentLocale: true,
  lessLoaderOptions: {
    javascriptEnabled: true,
  },
  disableRedirectHoist: true,
  cssLoaderOptions: {
    modules: true,
    getLocalIdent: (context, _, localName) => {
      if (
        context.resourcePath.includes('node_modules') ||
        context.resourcePath.includes('ant.design.pro.less') ||
        context.resourcePath.includes('global.less')
      ) {
        return localName;
      }

      const match = context.resourcePath.match(/src(.*)/);

      if (match && match[1]) {
        const antdProPath = match[1].replace('.less', '');
        const arr = slash(antdProPath)
          .split('/')
          .map(a => a.replace(/([A-Z])/g, '-$1'))
          .map(a => a.toLowerCase());
        return `antd-pro${arr.join('-')}-${localName}`.replace(/--/g, '-');
      }

      return localName;
    },
  },
  manifest: {
    basePath: '/',
  },
  chainWebpack: webpackPlugin,
  proxy: {
    '/api/': {
      target: 'http://localhost:8080/',
      changeOrigin: true,
    },
  },
};
