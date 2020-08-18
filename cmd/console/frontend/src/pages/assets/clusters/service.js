import request from "@/utils/request";

export async function queryAssetsList(params) {
  return request("/api/v1/assets/clusters", {
    params
  });
}
