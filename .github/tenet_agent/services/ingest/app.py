import os
import sys
from services.utils.env_validator import validate_env_vars

# TENET: Define the required environment variables for the Ingest service.
# This centralizes configuration requirements and their expected types,
# ensuring consistency and clarity for deployment.
REQUIRED_ENV_VARS = {
    "INGEST_SERVICE_PORT": int,
    "INGEST_DB_HOST": str,
    "INGEST_DB_PORT": int,
    "INGEST_DB_USER": str,
    "INGEST_DB_PASSWORD": str,
    "INGEST_QUEUE_URL": str,
    "INGEST_LOG_LEVEL": str, # Only presence and string value required
}

# TENET: Perform early validation of critical environment variables at service startup.
# This implements a fail-fast mechanism, preventing the service from running with
# incomplete or malformed configuration, which is crucial for operational stability.
try:
    CONFIG = validate_env_vars(REQUIRED_ENV_VARS)
    print("TENET: All required environment variables validated successfully for Ingest service.")
except ValueError as e:
    print(f"TENET: CRITICAL ENVIRONMENT CONFIGURATION ERROR for Ingest service:\n{e}")
    # TENET: Exit immediately if essential configuration is missing or invalid.
    # This prevents undefined behavior and provides clear, actionable feedback.
    sys.exit(1)

# --- Application Logic Starts Here ---
# TENET: Use the validated configuration dictionary throughout the application.
# This avoids repeated os.getenv calls, ensures type safety, and centralizes
# access to configuration, improving maintainability.

INGEST_SERVICE_PORT = CONFIG["INGEST_SERVICE_PORT"]
INGEST_DB_HOST = CONFIG["INGEST_DB_HOST"]
INGEST_DB_PORT = CONFIG["INGEST_DB_PORT"]
INGEST_DB_USER = CONFIG["INGEST_DB_USER"]
INGEST_DB_PASSWORD = CONFIG["INGEST_DB_PASSWORD"]
INGEST_QUEUE_URL = CONFIG["INGEST_QUEUE_URL"]
INGEST_LOG_LEVEL = CONFIG["INGEST_LOG_LEVEL"]

print(f"TENET: Ingest service configured with port: {INGEST_SERVICE_PORT}")
print(f"TENET: Connecting to DB at {INGEST_DB_HOST}:{INGEST_DB_PORT} as user {INGEST_DB_USER}")
print(f"TENET: Using queue: {INGEST_QUEUE_URL}")
print(f"TENET: Log level set to: {INGEST_LOG_LEVEL}")

def run_ingest_service():
    """
    Placeholder for the actual ingest service startup logic.
    This function would typically initialize database connections,
    message queue consumers, web servers, etc., using the validated
    environment configuration.
    """
    print(f"TENET: Ingest service running on port {INGEST_SERVICE_PORT}...")
    # Example: Initialize database connection, message queue consumer, etc.
    # from my_db_module import connect_to_db
    # from my_queue_module import create_queue_consumer
    # from my_web_server_module import start_web_server

    # db_connection = connect_to_db(
    #     host=INGEST_DB_HOST,
    #     port=INGEST_DB_PORT,
    #     user=INGEST_DB_USER,
    #     password=INGEST_DB_PASSWORD
    # )
    # queue_consumer = create_queue_consumer(INGEST_QUEUE_URL)
    # start_web_server(port=INGEST_SERVICE_PORT, log_level=INGEST_LOG_LEVEL)

if __name__ == "__main__":
    run_ingest_service()