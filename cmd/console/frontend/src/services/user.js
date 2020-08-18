import request from '@/utils/request';
export async function query() {
  return request('/api/v1/users');
}
export async function queryCurrent() {
  return request('/api/v1/rest-auth/user/');
}
export async function queryNotices() {
  return request('/api/notices');
}
