import request from '@/utils/request';
export async function fakeAccountLogin(params) {
  return request('/api/v1/rest-auth/login/', {
    method: 'POST',
    data: params,
  });
}
export async function getFakeCaptcha(mobile) {
  return request(`/api/v1/rest-auth/login/?mobile=${mobile}`);
}
