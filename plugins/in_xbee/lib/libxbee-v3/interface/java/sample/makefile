run: main.class
	LD_LIBRARY_PATH=.. java -classpath .:../libxbee.jar $(patsubst %.class,%,$^)

%.class: %.java
	javac -classpath .:../libxbee.jar $^
