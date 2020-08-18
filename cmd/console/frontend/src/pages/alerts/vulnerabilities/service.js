import request from '@/utils/request';

export async function queryTags() {
  return request('/api/v1/alarms/vulnerabilities/tags');
}

export async function queryVulns() {
  return request('/api/v1/alarms/vulnerabilities');
}
