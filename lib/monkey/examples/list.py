import monkey
import subprocess

content = ''

def list_cb(vhost, url, get, get_len, post, post_len, header):
    global content
    content = "<html><body><h2>Hello friend. You asked for %s.</h2>\n"
    content += "<pre>"
    content += subprocess.check_output(['ls', '-lh', '/tmp'])
    content += "</pre></body></html>"

    ret = {}
    ret['return'] = 1
    ret['content'] = content
    ret['content_len'] = len(ret['content'])

    return ret

monkey.init(None, 0, 0, None)
monkey.set_callback('data', list_cb)
monkey.start()
raw_input("Press enter to stop the server...")
monkey.stop()
