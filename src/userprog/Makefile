include ../Makefile.kernel


res:
	make clean	
	make

tes:
	make clean
	make
	pintos -v -k -T 300 --qemu  --filesys-size=2 -p build/tests/filesys/base/syn-read -a syn-read -p build/tests/filesys/base/child-syn-read -a child-syn-read -- -q  -f run syn-read
ges:
	make res
	pintos -v -k -T 60 --qemu  --filesys-size=2 -p build/tests/userprog/rox-child -a rox-child -p build/tests/userprog/child-rox -a child-rox -- -q  -f run rox-child

g:
	make res
	make grade

ses:
	make res
	pintos -v -k -T 360 --qemu  --filesys-size=2 -p build/tests/userprog/no-vm/multi-oom -a multi-oom -- -q  -f run multi-oom
