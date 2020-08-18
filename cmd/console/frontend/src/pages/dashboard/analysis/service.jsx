import request from '@/utils/request';

export async function chartData(start, end) {
  return request('/api/v1/overall/analysis_chart', {
    params: {start: start, end: end}
  });
}
