
from flask import Flask

test_app = Flask(__name__)


@test_app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>WebVulnLab Local Test</title>
    </head>
    <body>
        <h1>WebVulnLab Test Website</h1>
        <p>This is a local website for testing security headers.</p>
    </body>
    </html>
    """


if __name__ == "__main__":
    test_app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )
