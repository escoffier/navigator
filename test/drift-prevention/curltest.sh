httpaddrport=172.21.0.72:8000
echo "##################download big file##########################"
date
for i in $(seq 1 5)
do
echo "round $i"
time curl -O -s http://$httpaddrport/faulty.tar > /dev/null
rm -rf faulty.tar
done
date
echo "############################################################"

echo "#######################################download small file##########################"
date
for i in $(seq 1 100)
do
echo "round $i"
time curl -O -s http://$httpaddrport/$i.txt > /dev/null
rm -rf $i.txt
done
date
echo "############################################################"
