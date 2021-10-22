include ../Makefile.kernel


res:
	make clean	
	make

tes:
	make clean
	make
	pintos -v -k -T 60 --qemu  --filesys-size=2 -p build/tests/userprog/args-single -a args-single -- -q  -f run 'args-single onearg'
