import request from '@/utils/request';

export async function queryContainerDetail(params) {
  return request('/api/v1/detail/container', {
    params,
  });
}
