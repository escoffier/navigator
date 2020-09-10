Random TODO notes.


# Frontend

Need to scout which apis are mocked, which are broken, which are connected to backend.

---

Need to fix localizations to English.

---

when changing _mock.js, git commit eslint hook fails.


# Ops

mongodbDatabase: elasticalert # NOTE: we need to create elasticalert database as well.

---

sending context to docker deamon too slow, fix making projects.

---

/var/lib/postgresql/clair should probably be mounted as persistent volume

---

improve auth for postgres (currently it's hardcoded to posgtres/password to match https://github.com/arminc/clair-local-scan/blob/master/.travis.yml).

---

is securityContext change for postgres ok? See comment.

---

ports and service names that connect to each other are right now hardcoded in subcharts/*/template/deployment as command args.
THis should be specificied in top-level chart.yaml I think.

---

cleanup the mess with service/pod prefixes. Some have vegeta-* prefix, and some don't. note: this messes with hardcoded service
names in subcharts/*/template/deployment which are being passed as command args.

---

Maybe Clair and Scanner should be in the same pod? Note: clair-db maybe should be in another pod.

---

Elastic and etcd have default auth

# Backend

console requries JWT to access scanner API (acts like proxy). However, scanner API doesn't require JWT token, completely bypassing the security mechanism.

---

(scanner, console): mongo authSource database should be a separate command line argument argument.

---

swagger site doesn't work properly, suggests some problem with model?
http://10.152.183.24:8889/swagger/index.html#/default/v1-rest-auth-user
curl doesn't send proper json body, it only sends -d "password"

---

clair-address and clair-port refer to Scanner Service address. Clair service needs to have access to layers published by Scanner service.
Path to them is sent in Scan request to Clair. TODO: maybe rename? I spent hours on this because I was confused.

---

Console: scanner/heartbeat seems to be wrong path. 