import request from '@/utils/request';

export async function queryImageDetail(params) {
  return request('/api/v1/detail/image', {
    params,
  });
}
