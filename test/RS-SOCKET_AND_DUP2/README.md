To simulate this attack spin off two pods. In one of the pods please run
```bash
nc -l -p 1234
```
Then change the `script.sh` script to include the abovementioned pod IP address and run this script in the other pod
