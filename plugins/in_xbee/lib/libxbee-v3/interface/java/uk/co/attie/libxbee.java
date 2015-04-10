package uk.co.attie;

public class libxbee {
	public native void print();

	static {
		System.loadLibrary("xbee_java");
	}
}
