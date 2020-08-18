import request from '@/utils/request';

export async function queryRulesList(params) {
  return request('/api/v1/profiles/rules', {
    params,
  });
}
