import asyncio
import aiohttp
import subprocess
import argparse
import time
import os
import json

# Global counters
stats = {
    'tests_run': 0,
    'crashes_found': 0,
    'new_findings': 0,
    'start_time': time.time(),
}

crash_dir = "crashes"
os.makedirs(crash_dir, exist_ok=True)


async def generate_fuzz_input(original_input: str) -> str:
    """Uses Radamsa to generate fuzzed input."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "radamsa",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate(input=original_input.encode())
        return stdout.decode("latin-1")
    except Exception as e:
        return None


async def send_request(session, url, method, headers, data):
    try:
        start_time = time.time()

        content_type = headers.get("Content-Type", "")
        if method.upper() == "GET":
            async with session.get(url, headers=headers, params=data) as resp:
                status = resp.status
                text = await resp.text()
                resp_headers = dict(resp.headers)
        elif method.upper() == "POST":
            if content_type == "application/json":
                try:
                    parsed_data = json.loads(data)
                except:
                    parsed_data = data  # fallback
                async with session.post(url, headers=headers, json=parsed_data) as resp:
                    status = resp.status
                    text = await resp.text()
                    resp_headers = dict(resp.headers)
            else:
                async with session.post(url, headers=headers, data=data) as resp:
                    status = resp.status
                    text = await resp.text()
                    resp_headers = dict(resp.headers)
        else:
            return None, 0, "", {}

        end_time = time.time()
        return status, end_time - start_time, text, resp_headers
    except Exception as e:
        return None, 0, f"[EXCEPTION] {str(e)}", {}


def check_for_crash(status, response_text):
    if status is None or (500 <= status < 600):
        return True
    if "exception" in response_text.lower() or "traceback" in response_text.lower():
        return True
    return False


async def fuzzer_worker(session, args):
    try:
        while True:
            fuzzed = await generate_fuzz_input(args.payload)
            if not fuzzed:
                continue

            status, response_time, response_text, response_headers = await send_request(session, args.url, args.method, args.headers, fuzzed)
            stats['tests_run'] += 1

            if check_for_crash(status, response_text):
                stats['crashes_found'] += 1
                stats['new_findings'] += 1
                filename = os.path.join(crash_dir, f"crash_{int(time.time())}.txt")
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"Status Code: {status}\n")
                    f.write(f"Response Time: {response_time:.4f} seconds\n")
                    f.write("Response Headers:\n")
                    for key, value in response_headers.items():
                        f.write(f"  {key}: {value}\n")
                    f.write(f"\nFuzzed Input:\n{fuzzed}\n")
                    f.write(f"\nResponse Body:\n{response_text}")

            # Optional periodic console update
            if stats['tests_run'] % 100 == 0:
                elapsed = time.time() - stats['start_time']
                print(f"[INFO] Tests: {stats['tests_run']} | Crashes: {stats['crashes_found']} | Rate: {stats['tests_run']/elapsed:.2f} t/s")

            await asyncio.sleep(0.01)
    except asyncio.CancelledError:
        return


async def main():
    parser = argparse.ArgumentParser(description="Async HTTP Fuzzer with Radamsa")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", choices=["GET", "POST"], default="POST", help="HTTP method")
    parser.add_argument("--payload", required=True, help="Original payload for mutation")
    parser.add_argument("--headers", default='{}', help="HTTP headers as JSON string")
    parser.add_argument("--workers", type=int, default=5, help="Number of concurrent workers")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds to run")
    args = parser.parse_args()

    try:
        args.headers = json.loads(args.headers)
    except json.JSONDecodeError:
        print("Invalid JSON for headers")
        return

    connector = aiohttp.TCPConnector(ssl=False)
    print(f"Starting fuzzer for {args.duration} seconds with {args.workers} workers...")

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(fuzzer_worker(session, args)) for _ in range(args.workers)]
        try:
            await asyncio.sleep(args.duration)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    print(f"Fuzzing finished.\nTests Run: {stats['tests_run']} | Crashes: {stats['crashes_found']} | New Findings: {stats['new_findings']}")


if __name__ == "__main__":
    asyncio.run(main())
