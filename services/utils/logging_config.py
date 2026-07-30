import logging
import os
import json
import contextvars
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

# Context variable to hold correlation ID for the current request/async context
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)

class JSONFormatter(logging.Formatter):
    """Emit logs in structured JSON format."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": f"{datetime.utcnow().isoformat()}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Inject correlation ID if available
        correlation_id = correlation_id_var.get()
        if correlation_id:
            payload["correlation_id"] = correlation_id

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(payload)

def setup_logging(name: str) -> logging.Logger:
    """
    Set up logging configuration for a service.
    
    Args:
        name: Name of the logger (usually __name__)
    
    Returns:
        Configured logger instance

    Examples:
        >>> from services.utils.logging_config import setup_logging
        >>> logger = setup_logging(__name__)
        >>> logger.info("Service started")
        >>> logger.error("An error occurred", exc_info=True) 
    """
    logger = logging.getLogger(name)

    #add log level configurations from environment
    from services.utils.config import settings
    log_level_str = settings.LOG_LEVEL.upper()
    logger.setLevel(getattr(logging, log_level_str, logging.INFO))

    if not logger.handlers:
        formatter = JSONFormatter()

        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Set up file handler
        os.makedirs("logs", exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=os.path.join("logs", "tenet.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=3
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        logger.propagate = False
    
    return logger