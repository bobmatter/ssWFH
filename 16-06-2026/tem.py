import threading
import time
import webview

window = None

def worker():
    time.sleep(3)

    # Execute JavaScript in the webview
    window.evaluate_js("""
        document.body.innerHTML = '<h1>Updated from thread</h1>';
    """)

if __name__ == '__main__':
    window = webview.create_window(
        'My App',
        html='<h1>Hello</h1>'
    )

    threading.Thread(target=worker, daemon=True).start()

    webview.start()
    