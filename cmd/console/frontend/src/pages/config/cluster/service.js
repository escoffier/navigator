import request from '@/utils/request';

export async function postCluster(params) {
  return request('/api/v1/config/cluster', {
    method: 'POST',
    data: params
  });
}