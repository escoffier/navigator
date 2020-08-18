import request from '@/utils/request';

export async function queryNodeDetail(params) {
  return request('/api/v1/detail/node', {
    params,
  });
}
