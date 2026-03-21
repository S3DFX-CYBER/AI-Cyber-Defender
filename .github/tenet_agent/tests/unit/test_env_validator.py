import os
import pytest
from services.utils.env_validator import validate_env_vars

@pytest.fixture(autouse=True)
def clean_env():
    """Fixture to clean up environment variables after each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)

def test_all_required_vars_present_and_valid():
    os.environ["TEST_VAR_STR"] = "hello"
    os.environ["TEST_VAR_INT"] = "123"
    os.environ["TEST_VAR_BOOL"] = "True"

    required = {
        "TEST_VAR_STR": str,
        "TEST_VAR_INT": int,
        "TEST_VAR_BOOL": lambda x: x.lower() == 'true'
    }
    config = validate_env_vars(required)
    assert config == {
        "TEST_VAR_STR": "hello",
        "TEST_VAR_INT": 123,
        "TEST_VAR_BOOL": True
    }

def test_missing_one_required_var():
    os.environ["TEST_VAR_STR"] = "hello"
    # TEST_VAR_INT is missing

    required = {
        "TEST_VAR_STR": str,
        "TEST_VAR_INT": int
    }
    with pytest.raises(ValueError, match="Missing required environment variables: TEST_VAR_INT"):
        validate_env_vars(required)

def test_missing_multiple_required_vars():
    # Both are missing
    required = {
        "TEST_VAR_STR": str,
        "TEST_VAR_INT": int
    }
    with pytest.raises(ValueError, match="Missing required environment variables: TEST_VAR_STR, TEST_VAR_INT"):
        validate_env_vars(required)

def test_empty_string_is_missing():
    os.environ["TEST_VAR_STR"] = ""
    os.environ["TEST_VAR_INT"] = "123"

    required = {
        "TEST_VAR_STR": str,
        "TEST_VAR_INT": int
    }
    with pytest.raises(ValueError, match="Missing required environment variables: TEST_VAR_STR"):
        validate_env_vars(required)

def test_type_conversion_failure():
    os.environ["TEST_VAR_STR"] = "hello"
    os.environ["TEST_VAR_INT"] = "not_an_int"

    required = {
        "TEST_VAR_STR": str,
        "TEST_VAR_INT": int
    }
    with pytest.raises(ValueError, match="Environment variable conversion errors: 'TEST_VAR_INT'"):
        validate_env_vars(required)

def test_mixed_missing_and_conversion_errors():
    os.environ["TEST_VAR_INT"] = "not_an_int" # Conversion error
    # TEST_VAR_MISSING is missing

    required = {
        "TEST_VAR_INT": int,
        "TEST_VAR_MISSING": str
    }
    with pytest.raises(ValueError) as excinfo:
        validate_env_vars(required)
    
    assert "Missing required environment variables: TEST_VAR_MISSING" in str(excinfo.value)
    assert "'TEST_VAR_INT' (value: 'not_an_int') could not be converted to the required type." in str(excinfo.value)

def test_no_converter_means_string_type():
    os.environ["TEST_VAR_NO_CONVERTER"] = "some_value"
    os.environ["TEST_VAR_ANOTHER"] = "123"

    required = {
        "TEST_VAR_NO_CONVERTER": None, # Only presence check, defaults to string
        "TEST_VAR_ANOTHER": str # Explicit string conversion
    }
    config = validate_env_vars(required)
    assert config == {
        "TEST_VAR_NO_CONVERTER": "some_value",
        "TEST_VAR_ANOTHER": "123"
    }

def test_optional_vars_not_checked_if_not_in_required():
    os.environ["OPTIONAL_VAR"] = "present"
    required = {
        "TEST_VAR_STR": str
    }
    os.environ["TEST_VAR_STR"] = "required_value"
    config = validate_env_vars(required)
    assert "OPTIONAL_VAR" not in config # Only required vars are returned
    assert config["TEST_VAR_STR"] == "required_value"

def test_boolean_conversion():
    os.environ["BOOL_TRUE"] = "True"
    os.environ["BOOL_FALSE"] = "false"
    os.environ["BOOL_YES"] = "YES"
    os.environ["BOOL_NO"] = "no"
    os.environ["BOOL_ONE"] = "1"
    os.environ["BOOL_ZERO"] = "0"

    def to_bool(s: str) -> bool:
        return s.lower() in ('true', '1', 't', 'y', 'yes')

    required = {
        "BOOL_TRUE": to_bool,
        "BOOL_FALSE": to_bool,
        "BOOL_YES": to_bool,
        "BOOL_NO": to_bool,
        "BOOL_ONE": to_bool,
        "BOOL_ZERO": to_bool,
    }
    config = validate_env_vars(required)
    assert config == {
        "BOOL_TRUE": True,
        "BOOL_FALSE": False,
        "BOOL_YES": True,
        "BOOL_NO": False,
        "BOOL_ONE": True,
        "BOOL_ZERO": False,
    }

def test_boolean_conversion_invalid():
    os.environ["BOOL_INVALID"] = "not_a_bool"
    def to_bool(s: str) -> bool:
        if s.lower() in ('true', '1', 't', 'y', 'yes'): return True
        if s.lower() in ('false', '0', 'f', 'n', 'no'): return False
        raise ValueError("Invalid boolean value")

    required = {
        "BOOL_INVALID": to_bool
    }
    with pytest.raises(ValueError, match="Environment variable conversion errors: 'BOOL_INVALID'"):
        validate_env_vars(required)