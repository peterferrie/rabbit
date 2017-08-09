msvc:
		cl /nologo /O2 /Ot /DTEST test.c rabbit.c
gnu:
		gcc -DTEST -Wall -O2 test.c rabbit.c -otest	 
clang:
		clang -DTEST -Wall -O2 test.c rabbit.c -otest	    