import request from '@/utils/request';

export async function queryAlertList(params) {
  return request('/api/v1/alarms/alerts', {
    params,
  });
}
export async function removeAlertList(params) {
  const { count = 5, ...restParams } = params;
  return request('/api/v1/alarms/alerts', {
    method: 'POST',
    params: {
      count,
    },
    data: { ...restParams, method: 'delete' },
  });
}
export async function addAlertList(params) {
  const { count = 5, ...restParams } = params;
  return request('/api/v1/alarms/alerts', {
    method: 'POST',
    params: {
      count,
    },
    data: { ...restParams, method: 'post' },
  });
}
export async function updateAlertList(params) {
  const { count = 5, ...restParams } = params;
  return request('/api/v1/alarms/alerts', {
    method: 'POST',
    params: {
      count,
    },
    data: { ...restParams, method: 'update' },
  });
}
