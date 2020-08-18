import request from '@/utils/request';

export async function queryPolicyList(params) {
  return request('/api/v1/profiles/policies', {
    params,
  });
}
