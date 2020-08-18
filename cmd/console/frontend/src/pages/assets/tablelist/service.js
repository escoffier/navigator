import request from '@/utils/request';

export async function queryNode(params) {
  return request('/api/v1/nodes', {
    params,
  });
}

export async function queryNodeContainers(params) {
  return request('/api/v1/assets/containers', {
    params,
  });
}

// export async function removeNode(params) {
//   return request('/api/rule', {
//     method: 'POST',
//     data: { ...params, method: 'delete' },
//   });
// }
// export async function addNode(params) {
//   return request('/api/rule', {
//     method: 'POST',
//     data: { ...params, method: 'post' },
//   });
// }
// export async function updateNode(params) {
//   return request('/api/rule', {
//     method: 'POST',
//     data: { ...params, method: 'update' },
//   });
// }
