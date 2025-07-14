import asyncio
import aiohttp
import subprocess
import argparse
import time
import os
import json
import sys
import hashlib

# Global counters
stats = {
    'tests_run': 0,
    'crashes_found': 0,
    'new_findings': 0,
    'start_time': time.time(),
}

crash_dir = "crashes"
log_dir = "logs"
os.makedirs(crash_dir, exist_ok=True)
os.makedirs(log_dir, exist_ok=True)

MAX_TESTS_WITHOUT_CRASH = 100000
seen_responses = set()

log_file_path = os.path.join(log_dir, "fuzz_debug.log")
log_file = open(log_file_path, "a", encoding="utf-8")


async def generate_fuzz_input(original_input: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "radamsa",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate(input=original_input.encode())
        return stdout.decode("latin-1")
    except Exception as e:
        print(f"[ERROR] Failed to generate fuzz input: {e}")
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
                    parsed_data = data
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
        print(f"[ERROR] Request exception: {e}")
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

            status, response_time, response_text, response_headers = await send_request(
                session, args.url, args.method, args.headers, fuzzed)

            stats['tests_run'] += 1

            body_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
            if body_hash not in seen_responses:
                seen_responses.add(body_hash)
                log_file.write("\n=== UNIQUE RESPONSE DETECTED ===\n")
                log_file.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Status: {status}\n")
                log_file.write(f"Response Time: {response_time:.4f} sec\n")
                log_file.write("Headers:\n")
                for k, v in response_headers.items():
                    log_file.write(f"  {k}: {v}\n")
                log_file.write("\nRequest Sent:\n")
                log_file.write(fuzzed + "\n")
                log_file.write("\nResponse Body:\n")
                log_file.write(response_text + "\n")
                log_file.flush()

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

            if stats['tests_run'] >= MAX_TESTS_WITHOUT_CRASH and stats['crashes_found'] == 0:
                print("\n[INFO] 100,000 tests completed without a single crash. Stopping fuzzer.")
                for task in asyncio.all_tasks():
                    task.cancel()

            await asyncio.sleep(0.01)
    except asyncio.CancelledError:
        return


async def live_stats_updater():
    try:
        while True:
            elapsed = time.time() - stats['start_time']
            rate = stats['tests_run'] / elapsed if elapsed > 0 else 0
            sys.stdout.write("\033[F\033[K" * 6)
            print(f"Tests Run     : {stats['tests_run']}")
            print(f"Crashes Found : {stats['crashes_found']}")
            print(f"New Findings  : {stats['new_findings']}")
            print(f"Elapsed Time  : {int(elapsed)}s")
            print(f"Test Rate     : {rate:.2f} tests/sec")
            print(f"Goal          : Stop at {MAX_TESTS_WITHOUT_CRASH} without crash")
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        return


async def main():
    parser = argparse.ArgumentParser(description="Async HTTP Fuzzer with Radamsa")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", choices=["GET", "POST"], default="POST", help="HTTP method")
    parser.add_argument("--payload", required=True, help="Original payload for mutation")
    parser.add_argument("--headers", default='{}', help="HTTP headers as JSON string")
    parser.add_argument("--workers", type=int, default=5, help="Number of concurrent workers")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds to run")
    args = parser.parse_args()

    try:
        args.headers = json.loads(args.headers)
    except json.JSONDecodeError:
        print("Invalid JSON for headers")
        return

    connector = aiohttp.TCPConnector(ssl=False)
    print(f"Starting fuzzer for {args.duration} seconds with {args.workers} workers...\n")

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(fuzzer_worker(session, args)) for _ in range(args.workers)]
        stats_task = asyncio.create_task(live_stats_updater())
        try:
            await asyncio.sleep(args.duration)
        finally:
            for task in tasks:
                task.cancel()
            stats_task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(stats_task, return_exceptions=True)

    log_file.close()
    print(f"\nFuzzing finished.\nTests Run: {stats['tests_run']} | Crashes: {stats['crashes_found']} | New Findings: {stats['new_findings']}")


if __name__ == "__main__":
    asyncio.run(main())
