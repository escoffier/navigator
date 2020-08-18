import request from '@/utils/request';

export async function queryReportDetail(params) {
  return request('/api/v1/detail/report', {
    params,
  });
}
