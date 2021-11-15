# 生成ca私钥
/opt/homebrew/opt/openssl@1.1/bin/openssl genrsa -out ca.key 2048
# 生成ca数字证书
/opt/homebrew/opt/openssl@1.1/bin/openssl req -x509 -new -nodes -key ca.key  -days 36500 -out ca.crt

# 生成服务端私钥
/opt/homebrew/opt/openssl@1.1/bin/openssl genrsa -out server.key 2048
# 生成服务端数字证书
/opt/homebrew/opt/openssl@1.1/bin/openssl req -new -key server.key -config ssl.cnf -out server.csr

# 用ca私钥签发服务端的数字证书
/opt/homebrew/opt/openssl@1.1/bin/openssl x509 -req \
    -days 36500 \
    -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -extensions req_ext -extfile ssl.cnf \
    -out server.crt

# 生成客户端私钥
/opt/homebrew/opt/openssl@1.1/bin/openssl genrsa -out client.key 2048
# 生成客户端数字证书
/opt/homebrew/opt/openssl@1.1/bin/openssl req -new -key client.key -subj "/CN=eventcenter" -out client.csr
# # 用ca私钥签发客户端的数字证书
/opt/homebrew/opt/openssl@1.1/bin/openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile client.ext -out client.crt -days 36500

