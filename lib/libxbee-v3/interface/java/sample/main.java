import uk.co.attie.*;

class main {
	public static void main(String[] args) {
		new libxbee().print();
	}
	
	static {
		System.loadLibrary("xbee_java");
	}
}
