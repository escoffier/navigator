import request from '@/utils/request';

export async function queryHandleTask(params) {
  return request('/api/v1/detail/handletask', {
    params,
  });
}

export async function postHandleTask(params) {
  const { ...restParams } = params;
  return request('/api/v1/detail/handletask', {
    method: 'POST',
    data: { ...restParams, method: 'post' },
  });
}
