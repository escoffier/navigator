import request from '@/utils/request';

export async function postRule(params) {
  // TODO
  return request('/api/v1/detail/container', {
    params,
  });
}

export async function getRuleForm(params) {
  // TODO
  return request('/api/v1/detail/ruleform', {
    params,
  });
}

