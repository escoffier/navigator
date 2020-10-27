# TODO: kill this until it grows up
until [ -f /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id ]
do 
    echo "Waiting for evironment to be ready for ebpf"
    sleep 3 
done
echo "Environment ready"
/go/src/app/dist/tensordig --config /config/detection.yaml &
pid_to_delete=$!
sleep 120
/go/src/app/dist/tensordig --config /config/detection.yaml &
echo "Deleting ${pid_to_delete}"
kill -9 $pid_to_delete
wait
