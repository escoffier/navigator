import request from '@/utils/request';

export async function queryProjectNotice() {
  return request('/api/v1/overall/notice');
}
export async function queryActivities() {
  return request('/api/v1/overall/activities');
}
export async function fakeChartData() {
  return request('/api/v1/overall/chart');
}
export async function queryCurrent() {
  return request('/api/v1/rest-auth/user/');
}

export async function queryStat() {
  return request('/api/v1/overall/stat');
}
