from flask import Flask
import logging

# Create a Flask application instance
app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='logs/server.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

@app.route('/', methods=['GET'])
def index():
    # Log the request
    app.logger.info("Received request at '/' route")
    return "Server is running!"

if __name__ == '__main__':
    # Log server startup
    app.logger.info("Starting Flask server on port 5001")
    app.run(port=5001)
    # Log server shutdown
    app.logger.info("Flask server has stopped")
