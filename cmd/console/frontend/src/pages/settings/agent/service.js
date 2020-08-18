import request from '@/utils/request';

export async function queryClusters() {
  return request('/api/v1/config/clusters');
}

export async function queryAgents() {
  return request('/api/v1/config/agents');
}

export async function deleteCluster(params) {
  return request(`/api/v1/config/cluster/${params.name}`, {
    method: 'DELETE',
  });
}
