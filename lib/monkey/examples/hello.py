import monkey

f = open('/tmp/index.html', 'w')
f.write("<html><body><h2>Hello Monkey</h2></body></html>")
f.close()

monkey.init(None, 0, 0, '/tmp/')
monkey.configure(indexfile='index.html')

monkey.start()
raw_input("Press enter to stop the server...")
monkey.stop()
