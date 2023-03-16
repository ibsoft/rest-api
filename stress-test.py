import subprocess
import concurrent.futures


USERNAME = "susan"
PASSWORD = "password456"


def make_request(auth):
    cmd = f"curl -X POST -u {auth} http://localhost:5000/login"
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()

def run_stress_test(num_requests):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for i in range(num_requests):
            auth = f"{USERNAME}:{PASSWORD}"
            futures.append(executor.submit(make_request, auth))

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                # do something with result if needed
            except Exception as exc:
                print(f"Request generated an exception: {exc}")


if __name__ == "__main__":
    num_requests = 100
    run_stress_test(num_requests)
