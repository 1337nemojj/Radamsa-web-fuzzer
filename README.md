# Web Service Fuzzer with Radamsa

## Prerequisites

- Python 3.x
- Radamsa fuzzer
- `requests` Python library

## Installation

1.  **Install Radamsa**:
    If Radamsa is not already installed on your system, you can install it by cloning the repository and building it from source. First, ensure you have `build-essential` and `git` installed:

    ```bash
    sudo apt-get update
    sudo apt-get install -y build-essential git
    ```

    Then, clone the Radamsa repository and build:

    ```bash
    git clone https://gitlab.com/akihe/radamsa.git
    cd radamsa
    make
    sudo make install
    ```

2.  **Install Python Dependencies**:
    Install the `requests` library:

    ```bash
    pip install requests
    ```

## Usage

1.  **Configure the Fuzzer**:
Async HTTP Fuzzer with Radamsa
```
options:
  -h, --help           show this help message and exit
  --url URL            Target URL
  --method {GET,POST}  HTTP method
  --payload PAYLOAD    Original payload for mutation
  --headers HEADERS    HTTP headers as JSON string
  --workers WORKERS    Number of concurrent workers
  --duration DURATION  Duration in seconds to run
  ```

2.  **Run the Fuzzer**:
    Execute the `fuzzer.py` script from your terminal:

    ```bash
    python3 fuzzer.py
    ```

    The fuzzer will start, and you will see real-time updates in your console. You can stop the fuzzer at any time by pressing `Ctrl+C`.

## How it Works

-   **Input Generation**: For each test, Radamsa mutates the `original_payload` to generate a fuzzed input.
-   **Request Sending**: The fuzzer sends an HTTP request (GET or POST) with the fuzzed input to the `target_url`.
-   **Crash Detection**: The fuzzer monitors the server's response. A crash is primarily detected by HTTP 5xx status codes. If a crash is detected.
-   **Dynamic Thread Adjustment**: 
    -   If a crash is detected, the number of active threads is halved (down to a minimum of 1), and the server is temporarily marked as unhealthy to reduce load.
    -   If requests are consistently fast (response time < 0.5 seconds) and the server is healthy, the number of active threads is gradually increased (up to a maximum of 10). (SOON)
-   **Real-time Reporting**: The console interface updates every second, showing key metrics of the fuzzing process.(SOON)
-   **Stopping Conditions** (SOON): The fuzzer automatically stops if:
    -   The total number of tests reaches 100,000.
    -   No new crashes or findings are detected for 2 hours.


