import request from '@/utils/request';
``
export async function queryImage(params) {
  return request('/api/v1/assets/images', {
    params,
  });
}
export async function blockImage(params) {
  return request('/api/v1/assets/images', {
    method: 'POST',
    data: { ...params, method: 'delete' },
  });
}

export async function allowImage(params) {
  return request('/api/v1/assets/images', {
    method: 'POST',
    data: { ...params, method: 'post' },
  });
}

export async function scanImage(params) {
  return request('/api/v1/assets/images', {
    method: 'POST',
    data: { ...params, method: 'update' },
  });
}
