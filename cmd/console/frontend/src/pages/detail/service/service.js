import request from '@/utils/request';

export async function queryServiceDetail(params) {
  return request('/api/v1/detail/service', {
    params,
  });
}
