all: no-stack-protector stack-protector stack-protector-all stack-protector-strong


no-stack-protector:
	gcc -fno-stack-protector -o no-stack-protector tester.c

stack-protector:
	gcc -fstack-protector -o stack-protector tester.c

stack-protector-all:
	gcc -fstack-protector-all -o stack-protector-all tester.c

stack-protector-strong:
	gcc -fstack-protector-strong -o stack-protector-strong tester.c

clean:
	-rm *.o
	-rm *stack-protector*
