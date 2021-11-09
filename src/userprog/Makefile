include ../Makefile.kernel


res:
	make clean	
	make

tes:
	make clean
	make
	pintos -v -k -T 60 --qemu  --filesys-size=2 -p build/tests/userprog/read-normal -a read-normal -p ../tests/userprog/sample.txt -a sample.txt -- -q  -f run read-normal

ges:
	make res
	pintos -v -k -T 60 --qemu  --filesys-size=2 -p build/tests/userprog/rox-child -a rox-child -p build/tests/userprog/child-rox -a child-rox -- -q  -f run rox-child

g:
	make res
	make grade
