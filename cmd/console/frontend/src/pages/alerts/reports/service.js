import request from '@/utils/request';

export async function queryReports() {
  return request('/api/v1/alarms/reports');
}

export async function queryReportDetail(params) {
  return request('/api/v1/detail/report', {
    params
  })
}

export async function queryReportProblems() {
  return request('/api/v1/alarms/reports/problems')
}