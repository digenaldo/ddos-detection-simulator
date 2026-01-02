"""
Flask server for DDoS attack target simulation.
"""
from flask import Flask, jsonify
import logging
import sys
from typing import Dict

from config.settings import Config

# Logging configuration
def setup_logging() -> None:
    """Configure the logging system for the server."""
    Config.ensure_directories()
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper()),
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(Config.SERVER_LOG),
            logging.StreamHandler(sys.stdout)
        ]
    )


setup_logging()
logger = logging.getLogger(__name__)

# Create Flask instance
app = Flask(__name__)


@app.route('/', methods=['GET'])
def index() -> Dict[str, str]:
    """
    Main server endpoint.
    
    Returns:
        Dict with status message
    """
    logger.info("Request received at '/' route")
    return jsonify({
        "status": "online",
        "message": "Server is running!"
    })


@app.route('/health', methods=['GET'])
def health() -> Dict[str, str]:
    """
    Health check endpoint.
    
    Returns:
        Dict with health status
    """
    return jsonify({
        "status": "healthy",
        "service": "ddos-detection-simulator"
    })


@app.errorhandler(404)
def not_found(error) -> tuple:
    """Handler for routes not found."""
    logger.warning(f"Route not found: {error}")
    return jsonify({"error": "Route not found"}), 404


@app.errorhandler(500)
def internal_error(error) -> tuple:
    """Handler for internal errors."""
    logger.error(f"Internal error: {error}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500


def main() -> None:
    """Main function to start the server."""
    try:
        logger.info(f"Starting Flask server on port {Config.FLASK_PORT}")
        logger.info(f"Host: {Config.FLASK_HOST}")
        logger.info(f"Debug: {Config.DEBUG}")
        
        app.run(
            host=Config.FLASK_HOST,
            port=Config.FLASK_PORT,
            debug=Config.DEBUG
        )
    except Exception as e:
        logger.error(f"Error starting server: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Flask server stopped")


if __name__ == '__main__':
    main()
