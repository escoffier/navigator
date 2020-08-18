import request from '@/utils/request';

export async function postAgent(params) {
  const data = {
    type: params.type || 'monitor',
    namespace: params.namespace,
    etcd: params.ip
  };
  console.log(data);
  return request('/api/v1/config/agents', {
    method: 'POST',
    data: data
  });
}
