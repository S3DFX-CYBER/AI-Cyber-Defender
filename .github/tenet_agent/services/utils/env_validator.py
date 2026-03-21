import os
from typing import Callable, Dict, Any, Optional

def validate_env_vars(required_vars: Dict[str, Optional[Callable[[str], Any]]]) -> Dict[str, Any]:
    """
    Validates the presence and optionally the type of required environment variables.

    Args:
        required_vars: A dictionary where keys are environment variable names (str)
                       and values are optional type conversion functions (e.g., int, str, bool)
                       or None if only presence is required (defaults to string).
                       Example: {"PORT": int, "DB_HOST": str, "DEBUG_MODE": lambda x: x.lower() == 'true'}

    Returns:
        A dictionary containing the validated and type-converted environment variable values.

    Raises:
        ValueError: If any required environment variables are missing or fail type conversion.
    """
    missing_vars = []
    conversion_errors = []
    validated_config = {}

    for var_name, converter in required_vars.items():
        value = os.getenv(var_name)

        if value is None or value.strip() == "":
            missing_vars.append(var_name)
            continue

        try:
            if converter:
                # TENET: Attempt to convert the environment variable value to the specified type.
                # This ensures early detection of malformed configuration.
                validated_config[var_name] = converter(value)
            else:
                # If no converter is specified, treat it as a required string.
                validated_config[var_name] = value
        except ValueError:
            conversion_errors.append(f"'{var_name}' (value: '{value}') could not be converted to the required type.")
        except Exception as e:
            # TENET: Catch unexpected errors during conversion to provide robust error reporting.
            conversion_errors.append(f"'{var_name}' (value: '{value}') encountered an unexpected error during conversion: {e}")

    error_messages = []
    if missing_vars:
        error_messages.append(f"Missing required environment variables: {', '.join(missing_vars)}")
    if conversion_errors:
        error_messages.append(f"Environment variable conversion errors: {'; '.join(conversion_errors)}")

    if error_messages:
        # TENET: Fail-fast mechanism: raise a clear error if critical environment variables are misconfigured.
        raise ValueError("\n".join(error_messages))

    return validated_config