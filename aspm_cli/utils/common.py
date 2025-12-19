import os
import sys
import requests
import urllib3
# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
from colorama import Fore

from aspm_cli.utils.logger import Logger
from aspm_cli.utils.spinner import Spinner

# Moved from original main.py
ALLOWED_SCAN_TYPES = ["iac", "sq-sast", "secret", "container", "sast", "dast"]

def _build_endpoint_url(endpoint, api_path):
    """
    Build the full URL for API requests.
    If endpoint already includes protocol (http:// or https://), use it as-is.
    Otherwise, prepend https:// for production endpoints.
    """
    if endpoint.startswith(("http://", "https://")):
        return f"{endpoint}{api_path}"
    return f"https://{endpoint}{api_path}"

def clean_env_vars():
    """Removes surrounding quotes from all environment variables."""
    for key, value in os.environ.items():
        if value and (value.startswith(("'", '"')) and value.endswith(("'", '"'))):
            os.environ[key] = value[1:-1]

def print_banner():
    try:
        banner = r"""
        ╔═╗┌─┐┌─┐┬ ┬╦╔═┌┐┌┌─┐─┐ ┬  ╔═╗╔═╗╔═╗╔╦╗  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
        ╠═╣│  │  │ │╠╩╗││││ │┌┴┬┘  ╠═╣╚═╗╠═╝║║║  ╚═╗│  ├─┤││││││├┤ ├┬┘
        ╩ ╩└─┘└─┘└─┘╩ ╩┘└┘└─┘┴ └─  ╩ ╩╚═╝╩  ╩ ╩  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
        """
        print(Fore.BLUE + banner)
    except:
        # Skipping if there are any issues with Unicode chars
        print(Fore.BLUE + "ACCUKNOX ASPM SCANNER")

def upload_results(file_path, endpoint, label, token, tenant_id, data_type):
    upload_exit_code = 1
    """Uploads scan results to the AccuKnox endpoint."""
    
    if not data_type:
        Logger.get_logger().error("data_type is required for artifact uploads")
        return upload_exit_code
    
    if not os.path.exists(file_path):
        Logger.get_logger().warning(f"Result file not found: {file_path}. Skipping upload.")
        return upload_exit_code

    Logger.get_logger().info(f"Uploading scan results from {file_path} to {endpoint}...")
    headers = {
        "Authorization": f"Bearer {token}"
    }
    if tenant_id:
        headers["Tenant-Id"] = tenant_id
    api_path = "/api/v1/artifact/"
    params = {
        "data_type": data_type,
        "label_id": label,
        "save_to_s3": "true"
    }
    if tenant_id:
        params["tenant_id"] = tenant_id

    spinner = Spinner(message="Uploading scan results...")
    try:
        spinner.start()

        with open(file_path, 'rb') as file:
            url = _build_endpoint_url(endpoint, api_path)
            response = requests.post(
                url,
                headers=headers,
                params=params,
                files={"file": file},
                verify=False  # Bypass SSL verification
            )
            response.raise_for_status()

        spinner.stop()
        Logger.log_with_color('INFO', "Scan results uploaded successfully!", Fore.GREEN)
        Logger.get_logger().debug(f"Response: {response.json()}")
        upload_exit_code = 0

    except requests.exceptions.Timeout:
        spinner.stop()
        Logger.get_logger().error("Upload timed out after 60 seconds.")
    except requests.exceptions.RequestException as e:
        spinner.stop()
        Logger.get_logger().error(f"Failed to upload scan results: {e}")
        if hasattr(e, 'response') and e.response is not None:
            Logger.get_logger().error(f"Response status: {e.response.status_code}")
            Logger.get_logger().error(f"Response body: {e.response.text}")
    except Exception as e:
        spinner.stop()
        Logger.get_logger().error(f"An unexpected error occurred during upload: {e}")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path) # Clean up result file after attempt
    return upload_exit_code

def handle_failure(exit_code: int, softfail: bool):
    """Handles the exit code of a scan, potentially exiting based on softfail."""
    if exit_code != 0:
        message = f"Scan completed with non-zero exit code: {exit_code}."
        if softfail:
            Logger.log_with_color('WARNING', f"{message} (Soft fail enabled, continuing.)", Fore.YELLOW)
        else:
            Logger.log_with_color('ERROR', f"{message} (Hard fail enabled, exiting.)", Fore.RED)
            sys.exit(exit_code)
    else:
        Logger.log_with_color('INFO', "Scan completed successfully with exit code 0.", Fore.GREEN)