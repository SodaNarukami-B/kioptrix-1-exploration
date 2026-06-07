all:
	gcc ./master.c ./lib/*/*.c ./src/*/*.c -o ./bin/main
	./bin/main
