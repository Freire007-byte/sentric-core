#!/bin/bash
cd ~/sentric-core/lab_routeros
BASE=chr-7.24.1.img
for vm in r1 r2; do
  [ -f $vm.qcow2 ] || sudo qemu-img create -f qcow2 -b $BASE -F raw $vm.qcow2
done
setup() {
  echo "=== setup $1 (a definir password) ==="
  ( sleep 35; printf "\n"; sleep 4; printf "admin\n"; sleep 4; printf "\n"; sleep 5; printf "/user set admin password=SentricLab2026\n"; sleep 5; printf "\n"; sleep 3 ) | sudo timeout 130 qemu-system-x86_64 -enable-kvm -m 256 -drive file=$1.qcow2,format=qcow2,if=virtio -netdev user,id=mgmt -device e1000,netdev=mgmt -display none -serial stdio || true
}
[ -f .r1_setup_done ] || { setup r1; touch .r1_setup_done; }
[ -f .r2_setup_done ] || { setup r2; touch .r2_setup_done; }
sudo pkill -f "qemu-system.*r[12].qcow2" 2>/dev/null; sleep 2
sudo qemu-system-x86_64 -enable-kvm -m 256 -drive file=r1.qcow2,format=qcow2,if=virtio -netdev user,id=mg,hostfwd=tcp::2221-:22 -device e1000,netdev=mg -netdev socket,id=lk,listen=:10001 -device e1000,netdev=lk -display none -daemonize -pidfile r1.pid -serial file:r1.console.log
sleep 3
sudo qemu-system-x86_64 -enable-kvm -m 256 -drive file=r2.qcow2,format=qcow2,if=virtio -netdev user,id=mg,hostfwd=tcp::2222-:22 -device e1000,netdev=mg -netdev socket,id=lk,connect=127.0.0.1:10001 -device e1000,netdev=lk -display none -daemonize -pidfile r2.pid -serial file:r2.console.log
echo "a aguardar boot do RouterOS..."; sleep 45
sshpass -p SentricLab2026 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -p 2221 admin@127.0.0.1 "/system identity set name=r1; /ip address add address=10.99.99.1/24 interface=ether2" && echo R1_OK
sshpass -p SentricLab2026 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -p 2222 admin@127.0.0.1 "/system identity set name=r2; /ip address add address=10.99.99.2/24 interface=ether2" && echo R2_OK
sshpass -p SentricLab2026 ssh -o StrictHostKeyChecking=no -p 2221 admin@127.0.0.1 "/ping 10.99.99.2 count=2" && echo LINK_OK
echo "=== LAB ROUTEROS NO AR: r1(10.99.99.1) <-> r2(10.99.99.2) ==="
